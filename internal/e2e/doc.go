// Package e2e holds end-to-end tests that run a real daemon (socket server,
// broker, vault, grants, audit, runner) in-process with the INSECURE dev
// backends. The tests are compiled only under the grantpin_dev build tag
// (`make dev-test`).
package e2e
