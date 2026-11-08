# ROADMAP — planned work, and how to pick it up

Twelve open items, tracked as GitHub issues **#130–#141** under three milestones, and on the
[project board](https://github.com/users/suryakencana007/projects/6). This file exists so a
future session does not have to query GitHub to find out what is next: it carries the evidence
pointer and the process rule for every item.

**Everything tamper-owned is closed.** `./tech-debt.md` holds one item, **TD-27**, and it is
Barista's migration rather than this library's. The items below are new work, not debt.

## The rule that decides order — not size

From `./tech-debt.md` §Process limits: any change touching **`identity`, `crypto/jwt.go`,
`oidc`, `saml`, `scim`, `espresso`, or `audit` needs a phase sketch (or an amendment to the
existing one) **merged before any code**. `PHASE7-MULTITENANCY-SKETCH.md` is a design freeze.

So the items below are labelled honestly: a two-line diff in `saml` still needs a paragraph of
sketch, and a large doc change needs none.

## Milestone 1 · Small hardening

| Issue | Sketch? | What to read first |
|---|---|---|
| [#130](https://github.com/suryakencana007/tamper/issues/130) `saml`: validate `MetadataURL` as an absolute URL | **yes** (PHASE17 amendment) | `saml/provider.go` — the `ACSURL` check added in #124 is the twin; PHASE17's "worth its own item" note |
| [#131](https://github.com/suryakencana007/tamper/issues/131) CI: a `gofmt` gate, after making the sqlc comment gofmt-stable | no | `audit/internal/sqlitestore/sqltypes/blob.go` — read the comment **before** running `gofmt -w`, which would corrupt the SQL literal `x''` into a curly quote |

## Milestone 2 · Proof and documentation

| Issue | Sketch? | What to read first |
|---|---|---|
| [#132](https://github.com/suryakencana007/tamper/issues/132) Audit crewjam's tags for namespace-blind matches beyond `NameID` | **yes** | PHASE17: *"the audit is this one path"*; `crewjam/saml@v0.5.1` `service_provider.go` |
| [#133](https://github.com/suryakencana007/tamper/issues/133) Prove or delete: guards whose mutants survive | no | two known cases: `espresso/scimroutes.go` (`!id.Valid()`) and `espresso/sagate.go` (actor `tenant.ID{}` vs `tenant.Single`) — both annotated in code as unproven |
| [#134](https://github.com/suryakencana007/tamper/issues/134) Compile the Go snippets in the documentation | no | `espresso`'s `docs_snippet_compile_test.go` is the model; the bug it prevents is my invented `identity.New(cfg, store, jwtSvc)` |
| [#135](https://github.com/suryakencana007/tamper/issues/135) An API reference, and versioned docs on the site | no | `docs/.vitepress/config.ts` sidebar; espresso publishes `docs/api/*` |

## Milestone 3 · New capability

| Issue | Sketch? | What to read first |
|---|---|---|
| [#136](https://github.com/suryakencana007/tamper/issues/136) WebAuthn/passkeys as a second factor | **yes** (new phase) | `crypto.AMR*` constants, `espresso.StepUpRequireMethods` — the gate already accepts a new method with no change |
| [#137](https://github.com/suryakencana007/tamper/issues/137) A shared `AssertionReplayStore` for multi-replica SAML | **yes** | `saml/provider.go`'s `BuildProvider` doc promises "a shared store for multiple replicas"; only the in-memory one ships |
| [#138](https://github.com/suryakencana007/tamper/issues/138) `PasswordPolicy` as a port | **yes** | the proven shape: `identity.SecondFactorPolicy` (0.12.0) and `ImpersonationPolicy` |
| [#139](https://github.com/suryakencana007/tamper/issues/139) Audit retention and compaction without breaking the chain | **yes**, + legal input | the M5 revisit condition in `CLAUDE.md`; commitment-based redaction is what exists today |
| [#140](https://github.com/suryakencana007/tamper/issues/140) Patch `crewjam/saml` upstream | no | PHASE17: the real fix is upstream; the CI allowance's removal condition is named in `.github/workflows/ci.yml` |
| [#141](https://github.com/suryakencana007/tamper/issues/141) A public demo of `examples/multitenant` | no | the live site, and `examples/multitenant`'s `TestOneBrowserHoldsASessionPerTenant` |

## How to start an item

1. **Read the issue** — it carries the evidence, the deliverable, and what the DoD must prove.
2. **Read the file it names.** Every item above points at the code or sketch that makes it
   concrete, because an item without its evidence is a wish.
3. **If the item says "sketch": write it and get it merged first.** A new phase sketch for new
   capability; an amendment for the existing one. This is the rule that has caught the most
   mistakes in this repository, including two designs that turned out to be wrong when checked
   against the code.
4. **Then follow a slice's habits**: tests first, every claim given a mutant, and the honest
   label for a mutant that cannot bite (`unobservable by measurement` / `unobservable by
   construction`) rather than a claim of proof.
5. **Close the loop in the same PR**: the changelog entry, the docs page (`docs/` — the site
   builds from it), and the issue itself with what was decided versus what was assumed.

## Standing rules any item must respect

These come from `CLAUDE.md` and are not negotiable in passing:

- `tenantID == ""` stays byte-identical to today's behaviour unless the item is the breaking
  flip itself.
- Deny by default, everywhere — including the absence of a decision.
- A cross-tenant miss is **404, never 403**: deny and miss must be indistinguishable.
- Misconfiguration fails at `New`, never as a per-request denial.
- tamper names no table. Ports and neutral records only.
- An optional-interface upgrade ships a boot guard **and** a test that the guard fires.
- An improvement spotted en route is a **separate change**, never smuggled into the current one.

## Definition of done, shared by all twelve

```
tests + mutants (each claim has one that goes red, or an honest "cannot bite")
gofmt · go vet · go test -race ./...        all clean
CHANGELOG entry                              under the next version
docs updated                                 docs/ pages + the site builds (0 dead links)
the issue closed with decisions vs assumptions named
```
