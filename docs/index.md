---
layout: home
title: tamper — multi-tenant auth for Go
titleTemplate: tamper

hero:
  name: tamper
  text: Multi-tenant auth for Go
  tagline: Tenancy, authorization, sessions, OIDC/SAML, SCIM and a tamper-evident audit log — behind ports your application implements.
  actions:
    - theme: brand
      text: What tamper is
      link: /guide/
    - theme: alt
      text: Install and run
      link: /guide/installation
    - theme: alt
      text: GitHub
      link: https://github.com/suryakencana007/tamper

features:
  - icon: 🏢
    title: Pooled tenancy
    details: One process, N tenants. The tenant is a type whose zero value denies, so "no tenant" is never read as "all tenants" — and a cross-tenant miss is a 404, never a 403.
  - icon: 🔐
    title: Authorization you can reverse
    details: A PDP with Check plus reverse queries ("who can do this?"), over two interchangeable engines — a rank RBAC and a set-based permission set — that a converter makes decide identically.
  - icon: 🪪
    title: Sessions that say what they proved
    details: acr names the policy class, amr names the methods. A step-up gate can require a second factor from a locally-enrolled TOTP session, not only from another IdP.
  - icon: 🔗
    title: Federation per tenant
    details: OIDC relying party and SAML service provider with store-backed, KEK-sealed providers, inherited from a tenant's ancestors when you want a shared IdP.
  - icon: 👥
    title: Provisioning with SCIM 2.0
    details: Filter engine, RFC 7644 PATCH, group-cycle detection — over store ports you supply, with the tenant always coming from the credential and never from the URL.
  - icon: 🧾
    title: A tamper-evident audit log
    details: A hash chain with boot-time verification, per-tenant export, and commitment-based redaction that discharges a deletion request without breaking the chain.
---

## What tamper is, in one paragraph

tamper is a set of Go packages that answer four questions for a multi-tenant
application: **who is this** (identity, federation), **what may they do** (authorization),
**which customer are they doing it for** (tenancy), and **what did they do**
(audit). Every one of those engines sits behind a port your application implements —
tamper names no table, owns no cookie brand, and freezes no audit vocabulary.

It is not a framework you adopt wholesale. You take the packages you need, mount the
routes you want through `espresso`, and keep your own schema.

## The shape of the thing

| Package | What it is |
|---|---|
| `tenant` | The tenancy vocabulary: `tenant.ID` (zero value denies), descriptors, entitlements, hierarchy walks and inherited plans |
| `authz` | The `Authorizer` PDP — `Check` and reverse queries — over a rank `RBAC` or a set-based `PermissionSet` |
| `identity` | Credentials and sessions: register, login, refresh, logout, TOTP enrolment, multi-IdP linking |
| `oidc` / `saml` | Relying-party and service-provider substrates, with per-tenant provider managers |
| `scim` | A SCIM 2.0 substrate: filters, PATCH, groups |
| `audit` | A hash-chained log with verification, per-tenant queries and commitment redaction |
| `crypto` | JWTs, bcrypt, refresh-token hashing, TOTP, and the KEK keyset that seals secrets at rest |
| `espresso` | The transport adapter: mountable route surfaces and the middleware that enforces all of the above |

## Where to start

- **New to tamper?** [Install and run](./guide/installation) takes you from an empty
  module to a working multi-tenant login in one file.
- **Evaluating the design?** The [design](./design/TAMPER-DESIGN) and
  [request flows](./design/flow) explain how the pieces fit, and the
  [ADRs](./adrs/) record why each decision went the way it did.
- **Upgrading?** The [changelog](./changelog) is generated from the repository's own
  `CHANGELOG.md`, and the [migration guides](./migrations/MIGRATION-v0.9) cover every
  breaking release.
- **Want to see it work?** Each [example](./examples/) is a runnable program with a
  specific claim it proves.
