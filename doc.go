// Package tamper is the root of the Tamper enterprise auth/authz framework —
// an embeddable, Go-native auth layer being extracted from Barista (Barista is
// its flagship + proving ground, mirroring Espresso <- Barista).
//
// Subpackages (lifted from Barista in later milestones per TAMPER-DESIGN.md):
//   - crypto: portable auth primitives (JWT / password / refresh / TOTP / keyset)
//   - authz:  the Authorizer PDP interface (Check / reverse queries) + backends
//   - audit:  tamper-evident hash-chain logging
//
// This is a skeleton created by the v1.x monorepo restructure; no code is
// lifted yet.
package tamper
