package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const statusWithoutInFlight = `{"version":"0.2.4","proto_v":1,"pid":4242,"started_at":"2026-10-25T14:15:46Z","vault_initialized":true,"keystore_tier":"hardware","approver_tier":"hardware","secrets":2,"active_grants":0}`

func TestStatusTellsAnOldDaemonsUnknownRunsFromZero(t *testing.T) {
	// A daemon from before 0.2.5 omits in_flight_runs; the JSON decoder would
	// make that a zero, which is not what the daemon said.
	st, known, err := decodeStatus(json.RawMessage(statusWithoutInFlight))
	if err != nil || known || st.InFlightRuns != 0 || st.Secrets != 2 {
		t.Fatalf("decode = %+v known=%v err=%v", st, known, err)
	}
	var out bytes.Buffer
	printStatus(&out, st, known, "/tmp/s.sock")
	if !strings.Contains(out.String(), "runs:         unknown (daemon predates 0.2.5)\n") || strings.Contains(out.String(), "in flight") {
		t.Errorf("status output = %q", out.String())
	}

	with := strings.TrimSuffix(statusWithoutInFlight, "}") + `,"in_flight_runs":0}`
	st, known, err = decodeStatus(json.RawMessage(with))
	if err != nil || !known || st.InFlightRuns != 0 {
		t.Fatalf("decode = %+v known=%v err=%v", st, known, err)
	}
	out.Reset()
	printStatus(&out, st, known, "/tmp/s.sock")
	if !strings.Contains(out.String(), "runs:         0 in flight\n") || strings.Contains(out.String(), "unknown") {
		t.Errorf("status output = %q", out.String())
	}

	busy := strings.TrimSuffix(statusWithoutInFlight, "}") + `,"in_flight_runs":3}`
	st, known, _ = decodeStatus(json.RawMessage(busy))
	out.Reset()
	printStatus(&out, st, known, "/tmp/s.sock")
	if !strings.Contains(out.String(), "runs:         3 in flight\n") {
		t.Errorf("status output = %q", out.String())
	}

	if _, _, err := decodeStatus(json.RawMessage(`not json`)); err == nil {
		t.Error("malformed status decoded")
	}
}
