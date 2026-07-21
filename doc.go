// Package tamper is the root of the Tamper enterprise auth/authz framework —
// an embeddable, Go-native auth layer extracted from Barista (Barista is its
// flagship + proving ground, mirroring Espresso <- Barista).
//
// Tamper is consumed import-not-copy: an application depends on the
// subpackages below directly (Barista wraps them in thin façades under
// internal/auth, internal/audit, internal/authz, internal/idp, and
// internal/scimstore). Every subpackage is store-decoupled behind a port
// interface the app implements; the framework never names a table.
//
// Shipped subpackages:
//
//   - crypto: portable auth primitives — JWT issue/verify, bcrypt password
//     hashing, refresh-token hashing, TOTP enrollment/verify, and the KEK
//     keyset + secretbox envelope that seals at-rest secrets (TOTP secrets,
//     OIDC/SAML provider secrets). Lifted in Phase 0b.
//   - audit: tamper-evident hash-chain logging — per-row canonical-version
//     dispatch, chain-segment anchors, boot-time chain verification — plus
//     the audit/sqlitestore SQLite persistence layer. Lifted in Phase 0c.
//   - authz: the Authorizer PDP — Check + reverse queries — over two
//     interchangeable engines: the downward-closed rank RBAC and the
//     set-based PermissionSet (which subsumes ranks and expresses
//     non-downward-closed roles), plus a converter that makes PermissionSet
//     decide identically to RBAC by construction. Phase 1.
//   - identity: the credentials + session core — Register/Login/Refresh/
//     Logout, refresh-session rotation + revocation, TOTP enrollment, and
//     multi-IdP account linking — behind one identity.Store port, with a
//     caller-supplied ACR and first-user bootstrap signal. Phase 2.
//   - oidc: the OIDC relying-party substrate (discovery + JWKS rotation,
//     PKCE, ID-token verification, group-claim normalization) and a
//     store-backed provider Manager with a TTL-cached live registry and
//     KEK-sealed client secrets. Phase 3.
//   - saml: the SAML service-provider substrate (crewjam/saml wrapping —
//     metadata fetch/parse, AuthnRequest building incl. step-up, assertion
//     helpers, signed state cookie) and the mirror-image provider Manager
//     with a KEK-sealed SP signing key. Phase 3.
//   - scim: the SCIM 2.0 substrate — the filter engine (parse + AST->SQL
//     over a caller-supplied column mapping), the RFC 7644 PATCH applier,
//     and group-cycle detection over a port. Phase 3.
//   - espresso: the first-class transport adapter for the Espresso HTTP
//     framework — mountable auth/OIDC/SAML/SCIM route surfaces plus the
//     RequireAuth / RequireAuthWS / RequireServiceAccount / RequireDecision /
//     RequireFreshAuth middleware and the Auditor mutation middleware. The
//     core stays transport-agnostic; other adapters are possible later.
//     Phase 4.
//
// The vision, niche, extraction playbook, and phase roadmap live in
// TAMPER-DESIGN.md next to this file. A top-level composition facade
// (tamper.New(Config) + tamper/espresso.Routes) and a runnable example are
// the current milestone — see PHASE6-STANDALONE-PACKAGING-SKETCH.md.
package tamper
