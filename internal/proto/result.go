package proto

import (
	"encoding/json"
	"time"

	"grantd/internal/presence"
)

// Op-specific payloads carried in Response.Result. Owners of each op may extend
// these additively (new optional fields only). None of them, except ShowResult,
// may ever contain a secret value.

// SecretInfo is one row of an OpList result (Result is []SecretInfo).
type SecretInfo struct {
	Name      string                `json:"name"`
	Tags      []string              `json:"tags,omitempty"`
	URL       string                `json:"url,omitempty"`
	Notes     string                `json:"notes,omitempty"`
	ExpiresAt *time.Time            `json:"expires_at,omitempty"`
	MinTier   presence.PresenceTier `json:"min_tier"`
	CreatedAt time.Time             `json:"created_at"`
	UpdatedAt time.Time             `json:"updated_at"`
}

// ExistsResult is the OpExists result.
type ExistsResult struct {
	Exists bool `json:"exists"`
}

// MaskedResult is the OpMasked result, e.g. "****WXYZ".
type MaskedResult struct {
	Masked string `json:"masked"`
}

// ShowResult is the OpShow result. It is the ONLY payload that carries a secret
// value; it is produced only for a presence-approved, TTY-attached CLI request
// and must never be served to the MCP shim. String redacts the value.
type ShowResult struct {
	Value string `json:"value"`
}

// String redacts the value.
func (ShowResult) String() string { return "proto.ShowResult{[REDACTED]}" }

// GoString redacts the value.
func (ShowResult) GoString() string { return "proto.ShowResult{[REDACTED]}" }

// GrantInfo is one row of an OpGrants list result (Result is []GrantInfo) and
// the result of OpGrants add (a single GrantInfo).
type GrantInfo struct {
	ID            string    `json:"id"`
	Caller        string    `json:"caller"`
	CwdPrefix     string    `json:"cwd_prefix"`
	Secrets       []string  `json:"secrets"`
	CmdPrefix     []string  `json:"cmd_prefix"`
	ExpiresAt     time.Time `json:"expires_at"`
	UsesRemaining *int      `json:"uses_remaining,omitempty"` // nil = unlimited within TTL
	CreatedAt     time.Time `json:"created_at"`
	// Standing: created by the human with `grants add`, not by the dialog's
	// "Allow for N".
	Standing bool `json:"standing,omitempty"`
	// Tampered: the stored row failed authentication (the vault file was edited
	// outside grantd). It never matches; the other fields are untrusted.
	Tampered bool `json:"tampered,omitempty"`
}

// AuditInfo is one row of an OpAudit list/export result (Result is []AuditInfo).
type AuditInfo struct {
	ID         string    `json:"id"`
	TS         time.Time `json:"ts"`
	Caller     string    `json:"caller"`
	Cwd        string    `json:"cwd"`
	Argv       []string  `json:"argv"`
	Secrets    []string  `json:"secrets"`
	Decision   string    `json:"decision"`
	GrantID    string    `json:"grant_id,omitempty"`
	ExitCode   *int      `json:"exit_code,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

// AuditExportResult is the OpAudit export result: the whole log as CSV text.
type AuditExportResult struct {
	CSV string `json:"csv"`
}

// AuditVerifyResult is the OpAudit verify result.
type AuditVerifyResult struct {
	OK         bool   `json:"ok"`
	Entries    int    `json:"entries"`
	FirstBadID string `json:"first_bad_id,omitempty"`
}

// StatusResult is the OpStatus result.
type StatusResult struct {
	Version          string                `json:"version"` // grantd build version
	ProtoV           int                   `json:"proto_v"`
	PID              int                   `json:"pid"`
	StartedAt        time.Time             `json:"started_at"`
	VaultInitialized bool                  `json:"vault_initialized"`
	KeyStoreTier     presence.PresenceTier `json:"keystore_tier"`
	ApproverTier     presence.PresenceTier `json:"approver_tier"`
	Secrets          int                   `json:"secrets"`
	ActiveGrants     int                   `json:"active_grants"`
	TamperedGrants   int                   `json:"tampered_grants,omitempty"` // grant rows that failed authentication
	Socket           string                `json:"socket,omitempty"`          // path the daemon listens on
}

// NewResult marshals v into a Response.Result payload.
func NewResult(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	return json.RawMessage(b), err
}
