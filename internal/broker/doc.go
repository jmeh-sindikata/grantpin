// Package broker implements the daemon's op handlers: it is the one place
// where policy, grants, the Approver, the vault, the runner and the audit log
// are composed (HANDOFF §4, §7).
//
// # Invariants
//
//   - No code path returns a plaintext secret except the show op, which is
//     presence-gated through the Approver on every call, never creates or
//     uses grants, and is audited before the value leaves the process.
//   - Every refusal, denial and failure of a run is written to the audit log.
//   - A request whose secrets need a stronger presence tier than the Approver
//     or the KeyStore provides is refused, never downgraded.
//   - Approver calls are serialised so an agent cannot stack overlapping
//     prompts in front of the human.
//   - Anything derived from a secret (error text, audit reasons) is passed
//     through a runner.Redactor built from the injected values before it
//     leaves the process.
//
// # run decision table
//
//	condition                                   response                       audit decision
//	malformed request                           bad_request/bad_request        error
//	policy unreadable/insecure/invalid          refused/policy_refused         refused_policy
//	policy forbids a secret or the command      refused/policy_refused         refused_policy
//	a secret name/glob resolves to nothing      not_found/secret_not_found     error
//	env var name invalid or colliding           bad_request/bad_request        error
//	a secret is expired                         refused/secret_expired         error
//	approver or keystore tier below min_tier    refused/tier_unmet             refused_tier
//	matching grant                              (runs)                         allowed_grant
//	human denies                                denied/user_denied             denied_user
//	prompt could not be shown                   denied/approver_unavailable    error
//	ctx done while waiting for the human        failed/timeout|canceled        error
//	human allows with a TTL                     (runs, grant stored)           allowed_new_grant
//	human allows once                           (runs)                         allowed_once
//	storing the new grant failed                failed/internal                error
//	resolving/decrypting failed                 failed/internal                error
//	process could not be started                failed/internal                error
//	command ran                                 ok, exit_code                  the allow decision
//
// A timed-out command reports ok with exit_code 124 and reason "timeout"; a
// command that is not found or cannot be executed reports ok with exit_code
// 127 or 126.
package broker
