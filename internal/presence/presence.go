// Package presence defines PresenceTier, the shared vocabulary for "how strongly
// is a human's presence verified".
//
// DECISION: PresenceTier lives in its own leaf package (rather than in keystore
// or approve) so that keystore, approve, policy, vault and proto can all import
// it without creating an import cycle or an artificial dependency between the
// two platform seams. It imports nothing from this module.
package presence

import (
	"fmt"
	"strings"
)

// PresenceTier says what a backend requires of the human (KeyStore: to unwrap
// the data key; Approver: to approve a release). Higher values are stronger,
// so tiers are comparable with >=.
//
// A request that cannot meet a secret's minimum tier is refused, never
// downgraded.
type PresenceTier int

const (
	// TierNone is headless / pre-grant only. No human verification.
	TierNone PresenceTier = iota
	// TierDialog is an OS dialog without biometrics (Linux default).
	TierDialog
	// TierHardware is Touch ID / Windows Hello / TPM-gated.
	TierHardware
)

// String returns the canonical lowercase name ("none", "dialog", "hardware").
// Unknown values render as "tier(N)".
func (t PresenceTier) String() string {
	switch t {
	case TierNone:
		return "none"
	case TierDialog:
		return "dialog"
	case TierHardware:
		return "hardware"
	default:
		return fmt.Sprintf("tier(%d)", int(t))
	}
}

// Valid reports whether t is one of the defined tiers.
func (t PresenceTier) Valid() bool { return t >= TierNone && t <= TierHardware }

// Meets reports whether t is at least as strong as min.
func (t PresenceTier) Meets(min PresenceTier) bool { return t >= min }

// ParseTier parses "none", "dialog" or "hardware" (case-insensitive, trimmed).
func ParseTier(s string) (PresenceTier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		return TierNone, nil
	case "dialog":
		return TierDialog, nil
	case "hardware":
		return TierHardware, nil
	default:
		return TierNone, fmt.Errorf("presence: unknown tier %q (want none, dialog or hardware)", s)
	}
}

// MarshalText implements encoding.TextMarshaler so tiers serialise as their
// names in JSON/YAML.
func (t PresenceTier) MarshalText() ([]byte, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("presence: invalid tier %d", int(t))
	}
	return []byte(t.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (t *PresenceTier) UnmarshalText(b []byte) error {
	v, err := ParseTier(string(b))
	if err != nil {
		return err
	}
	*t = v
	return nil
}
