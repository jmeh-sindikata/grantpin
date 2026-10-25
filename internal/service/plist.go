package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

// socketEnv mirrors daemon.SocketEnv (kept literal so this package has no
// dependency on the daemon package).
const socketEnv = "GRANTD_SOCKET"

type plistSpec struct {
	Label  string
	Exe    string
	Socket string
	// Path, if set, is exported to the daemon as PATH.
	Path   string
	OutLog string
	ErrLog string
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

var plistTmpl = template.Must(template.New("plist").Funcs(template.FuncMap{"x": xmlEscape}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{x .Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{x .Exe}}</string>
		<string>daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>StandardOutPath</key>
	<string>{{x .OutLog}}</string>
	<key>StandardErrorPath</key>
	<string>{{x .ErrLog}}</string>
{{- if or .Socket .Path}}
	<!-- PATH is recorded from the shell that ran "grantd service install" (or
	     taken from its path flag): launchd's own default lacks Homebrew and
	     friends, and the commands "grantd run" starts inherit the daemon's
	     environment by design. Nothing else from that shell is copied. -->
	<key>EnvironmentVariables</key>
	<dict>
{{- if .Path}}
		<key>PATH</key>
		<string>{{x .Path}}</string>
{{- end}}
{{- if .Socket}}
		<key>` + socketEnv + `</key>
		<string>{{x .Socket}}</string>
{{- end}}
	</dict>
{{- end}}
</dict>
</plist>
`))

func renderPlist(s plistSpec) ([]byte, error) {
	var b bytes.Buffer
	if err := plistTmpl.Execute(&b, s); err != nil {
		return nil, fmt.Errorf("service: render plist: %w", err)
	}
	return b.Bytes(), nil
}

func logPaths(dir string) (out, errp string) {
	return filepath.Join(dir, "daemon.out.log"), filepath.Join(dir, "daemon.err.log")
}

// parsePlist decodes the small subset of XML plists used here (dict, array,
// string, true, false, integer) into map[string]any / []any / string / bool /
// int64.
func parsePlist(data []byte) (map[string]any, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.Entity = xml.HTMLEntity
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("service: parse plist: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "dict" {
			v, err := parseDict(dec)
			if err != nil {
				return nil, err
			}
			return v, nil
		}
	}
}

func parseDict(dec *xml.Decoder) (map[string]any, error) {
	m := map[string]any{}
	var key string
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("service: parse plist dict: %w", err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return m, nil
		case xml.StartElement:
			if t.Name.Local == "key" {
				var k string
				if err := dec.DecodeElement(&k, &t); err != nil {
					return nil, fmt.Errorf("service: parse plist key: %w", err)
				}
				key = k
				continue
			}
			v, err := parseValue(dec, t)
			if err != nil {
				return nil, err
			}
			m[key] = v
		}
	}
}

func parseValue(dec *xml.Decoder, se xml.StartElement) (any, error) {
	switch se.Name.Local {
	case "dict":
		return parseDict(dec)
	case "array":
		var a []any
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("service: parse plist array: %w", err)
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return a, nil
			case xml.StartElement:
				v, err := parseValue(dec, t)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
		}
	case "true", "false":
		if err := dec.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	case "string", "integer":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return nil, fmt.Errorf("service: parse plist value: %w", err)
		}
		if se.Name.Local == "integer" {
			n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("service: parse plist integer: %w", err)
			}
			return n, nil
		}
		return s, nil
	default:
		if err := dec.Skip(); err != nil && err != io.EOF {
			return nil, err
		}
		return nil, nil
	}
}

// plistExe extracts ProgramArguments[0] from plist data.
func plistExe(data []byte) (string, error) {
	m, err := parsePlist(data)
	if err != nil {
		return "", err
	}
	args, _ := m["ProgramArguments"].([]any)
	if len(args) == 0 {
		return "", fmt.Errorf("service: plist has no ProgramArguments")
	}
	exe, _ := args[0].(string)
	if exe == "" {
		return "", fmt.Errorf("service: plist ProgramArguments[0] is not a string")
	}
	return exe, nil
}
