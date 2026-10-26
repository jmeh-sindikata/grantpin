package proto

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmeh-sindikata/grantpin/internal/presence"
)

// Version is the wire protocol version carried in Request.V.
const Version = 1

// Op names (Request.Op).
const (
	OpRun    = "run"    // execute argv with secrets injected; streams frames
	OpList   = "list"   // names + metadata, never values
	OpExists = "exists" // does secret Name exist
	OpMasked = "masked" // last 4 chars only (fully masked if shorter than 12)
	OpSet    = "set"    // store Value under Name (the human putting a secret in)
	OpDelete = "delete" // remove secret Name
	OpUpdate = "update" // change metadata of secret Name without touching its value
	OpShow   = "show"   // TTY-only, presence-gated; NEVER reachable via MCP
	OpGrants = "grants" // Action: list | add | revoke | revoke_all
	OpAudit  = "audit"  // Action: list | verify | export
	OpStatus = "status" // daemon/vault/backends status
)

// Ops lists every valid op name.
var Ops = []string{
	OpRun, OpList, OpExists, OpMasked, OpSet, OpDelete, OpUpdate, OpShow, OpGrants, OpAudit, OpStatus,
}

// Sub-actions (Request.Action) for OpGrants and OpAudit.
const (
	ActionList      = "list"       // grants, audit
	ActionAdd       = "add"        // grants: create a standing grant (human-approved)
	ActionRevoke    = "revoke"     // grants: revoke GrantID
	ActionRevokeAll = "revoke_all" // grants
	ActionVerify    = "verify"     // audit: check HMAC chain
	ActionExport    = "export"     // audit: all rows, caller renders CSV
)

// Stream names (StreamFrame.Stream).
const (
	StreamStdout = "stdout"
	StreamStderr = "stderr"
)

// Error categories (Response.Error). Coarse, stable, for programmatic handling;
// Reason carries the specific cause.
const (
	ErrDenied     = "denied"      // a human or missing grant said no
	ErrRefused    = "refused"     // a hard rule said no (policy, tier, peer, tty)
	ErrBadRequest = "bad_request" // malformed or unsupported request
	ErrNotFound   = "not_found"   // named object does not exist
	ErrFailed     = "failed"      // accepted but did not complete (timeout, cancel, internal)
)

// Reasons (Response.Reason). Specific cause; suggested Error category in
// parentheses.
const (
	ReasonUserDenied          = "user_denied"           // (denied) human pressed Deny
	ReasonNoGrant             = "no_grant"              // (denied) no matching grant and approver cannot prompt
	ReasonApproverUnavailable = "approver_unavailable"  // (denied) prompt could not be shown
	ReasonPolicyRefused       = "policy_refused"        // (refused) .grantpin.yml forbids secret/command
	ReasonTierUnmet           = "tier_unmet"            // (refused) backend tier below secret min_tier; never downgraded
	ReasonPeerRejected        = "peer_rejected"         // (refused) peer UID != daemon UID
	ReasonNotTTY              = "not_tty"               // (refused) show requires an interactive TTY
	ReasonBadRequest          = "bad_request"           // (bad_request) malformed fields
	ReasonUnsupportedVersion  = "unsupported_version"   // (bad_request) Request.V not supported
	ReasonUnknownOp           = "unknown_op"            // (bad_request)
	ReasonSecretNotFound      = "secret_not_found"      // (not_found)
	ReasonGrantNotFound       = "grant_not_found"       // (not_found)
	ReasonSecretExists        = "secret_exists"         // (bad_request) set without overwrite on an existing name
	ReasonSecretExpired       = "secret_expired"        // (refused) secret past expires_at
	ReasonVaultNotInitialized = "vault_not_initialized" // (failed)
	ReasonVaultLocked         = "vault_locked"          // (failed) vault exists but its key store is unavailable right now (screen locked); the daemon retries
	ReasonTimeout             = "timeout"               // (failed) command exceeded timeout_s
	ReasonCanceled            = "canceled"              // (failed) client went away / daemon shutting down
	ReasonInternal            = "internal"              // (failed) message must not contain secret values
	ReasonResponseTooLarge    = "response_too_large"    // (failed) the result would not fit in one protocol line
	ReasonBusy                = "busy"                  // (failed) the daemon has too many open connections; retry shortly
)

// Request is the single request line a client sends per connection. Only the
// fields relevant to Op are set; the rest are omitted on the wire.
//
// Value is the one field that carries a secret, and only for OpSet (the human
// putting a secret in). Request implements fmt.Stringer so that accidentally
// formatting a Request does not print Value.
type Request struct {
	V      int    `json:"v"`
	Op     string `json:"op"`
	Caller string `json:"caller,omitempty"` // informational, untrusted

	// run
	Cwd       string   `json:"cwd,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Secrets   []string `json:"secrets,omitempty"` // names or globs
	EnvPrefix string   `json:"env_prefix,omitempty"`
	TimeoutS  int      `json:"timeout_s,omitempty"`

	// exists / masked / set / delete / show
	Name string `json:"name,omitempty"`

	// set
	Value     string                 `json:"value,omitempty"` // SECRET: only for OpSet
	Tags      []string               `json:"tags,omitempty"`
	URL       string                 `json:"url,omitempty"`
	Notes     string                 `json:"notes,omitempty"`
	Expires   *time.Time             `json:"expires,omitempty"`   // absolute; CLI converts "30d"
	MinTier   *presence.PresenceTier `json:"min_tier,omitempty"`  // nil = vault default for platform
	Overwrite bool                   `json:"overwrite,omitempty"` // set: replace an existing Name

	// update: Name plus any subset of Tags, URL, Notes, Expires and MinTier
	// (the set fields above, with their omitempty rules: an absent field is
	// left unchanged). Clear names the fields to reset to empty/never, since
	// an empty value cannot be told from an absent one on the wire: any of
	// "tags", "url", "notes", "expires". Value and Overwrite are not used.
	Clear []string `json:"clear,omitempty"`

	// list
	Tag             string `json:"tag,omitempty"`               // filter by tag
	ExpiringWithinS int64  `json:"expiring_within_s,omitempty"` // only secrets expiring within N seconds

	// grants / audit
	Action  string `json:"action,omitempty"`
	GrantID string `json:"grant_id,omitempty"`
	Limit   int    `json:"limit,omitempty"` // audit list; 0 = daemon default
	// BeforeID pages audit list: only rows whose ID is below it (an ID as the
	// daemon returned it, a decimal string). Empty = start at the newest.
	BeforeID string `json:"before_id,omitempty"`

	// grants add (a standing grant). cwd, secrets and argv (the command
	// prefix) are the run fields above; Caller is who is asking, as always.
	// GrantCaller is the caller label the grant is FOR, required, and shown to
	// the human as claimed. TTLS is the lifetime in seconds (required, above
	// zero, at most the standing ceiling). Uses limits the number of releases
	// (0 = unlimited within the lifetime).
	GrantCaller string `json:"grant_caller,omitempty"`
	TTLS        int64  `json:"ttl_s,omitempty"`
	Uses        int    `json:"uses,omitempty"`
}

// String formats r without Value.
func (r Request) String() string {
	if r.Value != "" {
		r.Value = "[REDACTED]"
	}
	b, _ := json.Marshal(r)
	return string(b)
}

// GoString implements fmt.GoStringer with the same redaction as String.
func (r Request) GoString() string { return "proto.Request" + r.String() }

// Validate performs structural checks common to every op. Per-op field
// requirements are the daemon router's job.
func (r *Request) Validate() error {
	if r.V != Version {
		return fmt.Errorf("unsupported protocol version %d (want %d)", r.V, Version)
	}
	for _, op := range Ops {
		if r.Op == op {
			return nil
		}
	}
	return fmt.Errorf("unknown op %q", r.Op)
}

// StreamFrame carries redacted command output (0..n per OpRun, before the final
// Response). Data is already redacted by the daemon.
type StreamFrame struct {
	Stream string `json:"stream"` // StreamStdout | StreamStderr
	Data   string `json:"data"`
}

// Response is the final line of every exchange.
//
// ExitCode is a pointer so that exit code 0 is distinguishable from "no exit
// code" (non-run ops and failures before the command started).
type Response struct {
	OK       bool   `json:"ok"`
	ExitCode *int   `json:"exit_code,omitempty"`
	GrantID  string `json:"grant_id,omitempty"`
	AuditID  string `json:"audit_id,omitempty"`
	Error    string `json:"error,omitempty"`  // Err* category
	Reason   string `json:"reason,omitempty"` // Reason* cause
	// Message is optional human-readable detail for Error/Reason (for example
	// the policy item that was refused). It is already redacted by the daemon,
	// never carries a secret value, and is for display only: programs branch on
	// Error and Reason.
	Message string          `json:"message,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"` // op-specific payload (see result.go)
}

// IntPtr is a small helper for Response.ExitCode.
func IntPtr(v int) *int { return &v }
