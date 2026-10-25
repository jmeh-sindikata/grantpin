// Package approve defines the Approver seam: the component that asks the human
// for approval at secret-release time.
//
// Platform implementations live in subpackages (darwin today; windows and linux
// slot in later without touching core). The dev subpackage is a TierNone test
// backend compiled only under the grantd_dev build tag.
package approve
