// Package tamper is the root of the Tamper enterprise auth/authz framework —
// an embeddable, Go-native auth layer extracted from Barista (Barista is its
// flagship + proving ground, mirroring Espresso <- Barista).
//
// Shipped subpackages (import-not-copy; Barista consumes them via thin
// façades in internal/auth + internal/audit):
//   - crypto: portable auth primitives — JWT, password hashing, refresh
//     tokens, TOTP, KEK keyset + secretbox envelope encryption.
//     Lifted in Phase 0b (PR #402).
//   - audit: tamper-evident hash-chain logging (canonical-version dispatch,
//     chain anchors, boot-time verify) + the audit/sqlitestore persistence
//     layer. Lifted in Phase 0c (PR #403).
//
// Skeleton subpackages:
//   - authz: the Authorizer PDP interface (Check / reverse queries) +
//     pluggable backends. Phase 1 — next up.
//
// The vision, niche, extraction playbook, and phase roadmap (identity core,
// federation, transport adapter) live in TAMPER-DESIGN.md next to this file.
package tamper
