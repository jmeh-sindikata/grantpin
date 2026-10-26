// Package policy loads and evaluates per-repo .grantpin.yml files. Policy only
// restricts what a repo may request; it never grants access by itself.
//
// # Grant lifetimes: two different keys
//
//	max_grant_ttl           caps the "Allow for N" button of a release prompt
//	max_standing_grant_ttl  caps standing grants (optional)
//
// max_grant_ttl (default 1h when absent) bounds grants that come out of the
// approval dialog, which an agent can trigger at any time. The dialog offers
// min(max_grant_ttl, 24h), and a grant created from it never exceeds that. It
// is deliberately NOT applied to standing grants: those are created by the
// human, on purpose, with `grantpin grants add`, usually for days or weeks, in
// front of a dialog that states the duration and a Touch ID prompt. The dialog
// cap exists for agent-triggered prompts. Applying it (its default is 1h)
// would make every standing grant fail unless each repo opted in.
//
// max_standing_grant_ttl is the repo's own optional ceiling for standing
// grants, in the same duration syntax ("30d", "12h"). Absent means no repo
// ceiling; the daemon's global ceiling (90 days) always applies as well and
// the lower of the two wins. Because a policy file is written by whoever can
// write the repository, this key can only tighten the ceiling, never loosen
// the global one. A request above the ceiling is refused, not shortened.
package policy
