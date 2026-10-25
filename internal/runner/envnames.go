package runner

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	// ErrInvalidSecretName is returned by EnvNames for a secret name outside
	// [A-Za-z0-9_/.-]+ or with an empty path segment.
	ErrInvalidSecretName = errors.New("runner: invalid secret name")
	// ErrInvalidEnvName is returned when a derived (or supplied) environment
	// variable name is not a valid POSIX name.
	ErrInvalidEnvName = errors.New("runner: invalid environment variable name")
	// ErrEnvCollision is returned when two secrets cannot be given distinct
	// environment variable names.
	ErrEnvCollision = errors.New("runner: environment variable name collision")
)

var (
	secretNameRE = regexp.MustCompile(`^[A-Za-z0-9_/.-]+$`)
	// posixEnvRE is what EnvNames produces: uppercase POSIX names.
	posixEnvRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	// anyEnvRE is what Run accepts for Spec.Env keys (injected names).
	anyEnvRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// EnvNames maps secret names to environment variable names per HANDOFF §8.
//
//   - The default name is the last path segment, uppercased, with '.' and '-'
//     replaced by '_': "aws/access_key" -> ACCESS_KEY, "db/pg-url" -> PG_URL.
//   - If two or more distinct secrets would get the same default name, ALL of
//     the colliding ones use their full name instead, with '/', '.' and '-'
//     replaced by '_' and uppercased: "aws/access_key" -> AWS_ACCESS_KEY.
//     Non-colliding secrets keep their short names.
//   - prefix, if non-empty, is prepended verbatim to every name. It is not
//     case-folded: a prefix that makes a name invalid (e.g. "app_") is an error
//     rather than being silently rewritten.
//
// Every resulting name must match ^[A-Z_][A-Z0-9_]*$ and be unique; otherwise
// an error wrapping ErrInvalidEnvName or ErrEnvCollision is returned and no
// partial result is produced. Duplicate entries in secretNames are collapsed.
// The returned map is secretName -> envName. Error text contains secret names
// and env names only, never values.
func EnvNames(secretNames []string, prefix string) (map[string]string, error) {
	uniq := make([]string, 0, len(secretNames))
	seen := make(map[string]bool, len(secretNames))
	for _, n := range secretNames {
		if err := checkSecretName(n); err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			uniq = append(uniq, n)
		}
	}

	short := make(map[string][]string, len(uniq)) // default env name -> secrets
	for _, n := range uniq {
		d := envify(n[strings.LastIndexByte(n, '/')+1:])
		short[d] = append(short[d], n)
	}

	out := make(map[string]string, len(uniq))
	for d, group := range short {
		for _, n := range group {
			if len(group) == 1 {
				out[n] = d
			} else {
				out[n] = envify(strings.ReplaceAll(n, "/", "_"))
			}
		}
	}

	byEnv := make(map[string]string, len(out))
	for _, n := range uniq { // input order => deterministic errors
		name := prefix + out[n]
		if !posixEnvRE.MatchString(name) {
			return nil, fmt.Errorf("%w: secret %q maps to %q", ErrInvalidEnvName, n, name)
		}
		if other, dup := byEnv[name]; dup {
			a, b := other, n
			if a > b {
				a, b = b, a
			}
			return nil, fmt.Errorf("%w: secrets %q and %q both map to %s", ErrEnvCollision, a, b, name)
		}
		byEnv[name] = n
		out[n] = name
	}
	return out, nil
}

func checkSecretName(n string) error {
	if !secretNameRE.MatchString(n) {
		return fmt.Errorf("%w: %q", ErrInvalidSecretName, n)
	}
	for _, seg := range strings.Split(n, "/") {
		if seg == "" {
			return fmt.Errorf("%w: %q has an empty path segment", ErrInvalidSecretName, n)
		}
	}
	return nil
}

func envify(s string) string {
	return strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(s))
}

// sortedKeys returns the keys of m in ascending order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
