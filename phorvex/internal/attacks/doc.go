// Package attacks is the home of the attacks service's code (docs/services/attacks.md):
// firing the catalogue attacks, running the harness, and serving the evidence they
// produce.
//
// The code still lives in package console, which cmd/attacks serves with
// console.ServiceAttacks. It moves here route by route, as
// docs/services/attacks-migration.md describes. The package belongs to the attacks
// domain (internal/archtest): it may import shared packages and cataloguev1, never
// package console.
package attacks
