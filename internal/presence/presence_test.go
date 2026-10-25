package presence

import (
	"encoding/json"
	"testing"
)

func TestParseTierAndString(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want PresenceTier
	}{{"none", TierNone}, {"dialog", TierDialog}, {"hardware", TierHardware}, {" Hardware ", TierHardware}} {
		got, err := ParseTier(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("ParseTier(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
	if _, err := ParseTier("biometric"); err == nil {
		t.Fatal("expected error for unknown tier")
	}
	if got := PresenceTier(42).String(); got != "tier(42)" {
		t.Fatalf("unknown String() = %q", got)
	}
	for _, tr := range []PresenceTier{TierNone, TierDialog, TierHardware} {
		back, err := ParseTier(tr.String())
		if err != nil || back != tr {
			t.Fatalf("round trip %v: %v, %v", tr, back, err)
		}
	}
}

func TestMeets(t *testing.T) {
	if !TierHardware.Meets(TierDialog) || TierDialog.Meets(TierHardware) || !TierNone.Meets(TierNone) {
		t.Fatal("Meets ordering wrong")
	}
}

func TestJSON(t *testing.T) {
	b, err := json.Marshal(struct{ T PresenceTier }{TierDialog})
	if err != nil || string(b) != `{"T":"dialog"}` {
		t.Fatalf("marshal = %s, %v", b, err)
	}
	var v struct{ T PresenceTier }
	if err := json.Unmarshal([]byte(`{"T":"hardware"}`), &v); err != nil || v.T != TierHardware {
		t.Fatalf("unmarshal = %v, %v", v, err)
	}
	if err := json.Unmarshal([]byte(`{"T":"x"}`), &v); err == nil {
		t.Fatal("expected error")
	}
}
