# Proof sweep — every guard, and whether its mutant can fail

A guard that no mutant can reach is worse than no guard: it is read as protection. This file
records a sweep of the repository's security-relevant checks, the mutant applied to each, and the
verdict. Two guards could not fail and were dealt with rather than kept; the rest bite.

Method, so it can be repeated: copy the tree, replace one condition with a constant (`false`, or
a comparison the branch was written to catch), `go build ./...`, then run the package's tests. A
mutant that does not compile is not a mutant — it is a broken edit, and it proves nothing.

## Bite (20)

First written as 14 with 20 rows underneath: the number was a memory, not a count. It is
checked now — `TestProofSweepCountsMatchItsRows` fails if the heading and the table disagree.

| Guard | Mutant | Where |
|---|---|---|
| SAML: the namespace guard is called | call removed | `saml/parse.go` |
| SAML: the namespace check itself | `Space != assertionNS` → `false` | `saml/nameid_ns.go` |
| SAML: a foreign namespace that is merely *different* is refused | compared against `""` instead | `saml/nameid_ns.go` |
| SAML: a nil replay store is refused at parse | check removed | `saml/parse.go` |
| SAML: a nil replay store is refused at construction | check removed | `saml/provider.go` |
| SAML: the response size bound applies | condition → `false` | `saml/parse.go` |
| SAML: zero means the documented default bound | zero → unbounded | `saml/maxresponse.go` + `parse.go` |
| SAML: an ACS URL must be absolute | validation loosened | `saml/provider.go` |
| SAML: the request builder refuses a relative target | invariant dropped | `saml/parse.go` |
| tenant: `New("")` is unset, not single | returns `Single` | `tenant/id.go` |
| identity: the process-wide switch is a floor | floor skipped | `identity/secondfactor.go` |
| identity: a policy that errors denies | error → allow | `identity/secondfactor.go` |
| identity: `AtLogin` is honoured | ignored | `identity/secondfactor.go` |
| espresso: a non-active tenant is refused | status check removed | `espresso/activetenant.go` |
| espresso: a status-store miss is a miss | `ErrNotFound` branch removed | `espresso/activetenant.go` |
| espresso: a tenant credential cannot reach the platform surface | scope check loosened | `espresso/sagate.go` |
| espresso: a platform credential cannot reach a tenant route | scope check loosened | `espresso/sagate.go` |
| espresso: an ambiguous platform credential is refused | tenant-id check removed | `espresso/sagate.go` |
| espresso: an identity-less credential is refused | check removed | `espresso/sagate.go` |
| scim: a platform credential reaches no store | `!ok` check removed | `espresso/scimroutes.go` |

## Could not fail — dealt with, not kept

| Guard | Why it could not fail | What was done |
|---|---|---|
| `scimTenant`'s `!id.Valid()` conjunct | the function it calls answers a valid id whenever it answers one at all (`FromStored` → `Single` for `""`, `New(v)` otherwise). The bound that actually fires is `!ok` | **Deleted.** The invariant moved to where it can be checked: `TestTenantOfPrincipal_AlwaysAnswersAValidIDOrFalse` pins the resolver's contract, and a mutant that returns `(zero, true)` now fails there |
| the audit actor's zero tenant id vs `tenant.Single` | the two produce identical stored bits (`TenantID: ""`), so no test can tell them apart | **Kept, and the label made machine-checked:** `TestActorService_ZeroAndSingleTenantAreIndistinguishable` asserts they are indistinguishable and would fail if `Single` ever gained a marker reaching `Actor` — at which point the choice becomes observable and must be decided again |

## What the sweep says about the codebase

Nothing else in this set could not fail. Where a guard is unreachable today but kept as protection
for a *future* shape, the code says so in a comment that names the reachable half and the
unreachable one — an unproven guard is labelled, never counted.

## The gate that could not fail — the vulnerability scan (#159)

The sweep above is about guards in the product. This is the same defect found **in the checks**, and
it is the most expensive instance because a blind security gate reports success.

**What it did.** The step in `ci.yml` parsed `govulncheck -json` output with

```python
for line in fh:
    obj = json.loads(line)
```

`govulncheck@v1.6.0` does **not** emit JSON-lines. It emits a stream of **pretty-printed** JSON
objects, each spanning many lines. So every line raised `JSONDecodeError`, every error was
`continue`d as "the stream mixes message kinds", `found` stayed empty, and the step passed. It had
passed on every run since it was written.

**How it was found.** A local scan reported twelve findings — including `GO-2026-6909` attributed to
`crewjam/saml@v0.6.3`, a version that carries the fix — while CI was green. The obvious reading was
"the advisory's metadata is stale". The correct reading, one probe later: the *parser* was blind.

**What the fix is.**

- The parser is a file, `scripts/vuln_gate.py`, and it parses the stream with `raw_decode`.
- It refuses to report clean when the report is unusable: no `config` message, no `SBOM`, an
  unparseable stream, or a **database older than 30 days** all exit non-zero. A scanner reading a
  stale snapshot reports exactly what a clean scan reports.
- It blocks only findings **reachable from this module**, by looking for this module in the trace —
  not by trace length. A vulnerable symbol in a dependency also carries a trace; that distinction
  was the second bug in the rewrite, caught by a fixture.
- The toolchain moved to a release with no open stdlib advisories (`go1.27.4`), which is a real fix
  rather than an allowance.
- One advisory is allow-listed, with its reason and its removal condition written beside it:
  `GO-2026-6909`, whose database entry says `Fixed in: NONE` even though upstream shipped the fix in
  v0.5.2 (upstream issue #693 tracks the metadata).

**The test that makes it impossible to re-break.** `vuln_gate_test.go` feeds the gate nine shapes —
a pretty-printed finding, a different finding, the allow-listed advisory, a module-level advisory, a
finding whose trace stays in a dependency, a missing `config`, a stale database, an unparseable
report, and a clean scan — and asserts each exit code. Against the real data the new gate **fails**
on the old toolchain (18 findings) and passes on the new one, which is the difference the old step
could not express.

**The lesson, stated once.** Every guard in this repository is now asked a second question: not only
"does it reject what it is meant to reject", but **"has it ever rejected anything"**. A check that has
only ever passed is a hypothesis.
