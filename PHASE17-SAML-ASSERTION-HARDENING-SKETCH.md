# Phase 17 — Harden the SAML subject identity (GO-2026-6909)

Status: **accepted 2026-11-06; implemented in the same PR** (a security patch: the sketch
and the fix land together because the CI gate is red until both do — see §4).

## 1. The advisory, verified

```
GO-2026-6909  Nil-pointer panic in validateAssertion and namespace-blind Subject.NameID
Module: github.com/crewjam/saml   Found in: v0.5.1   Fixed in: N/A
```

Checked upstream, not assumed: `go list -m -versions github.com/crewjam/saml` stops at
`v0.5.1`, the repository's tag list tops out there, and it publishes no releases. There is
**nothing to upgrade to**.

Two distinct defects in one ID:

1. **`validateAssertion` dereferences `assertion.Issuer` without a nil check**, when
   `ExpectedIDPEntityID` is non-empty and a signed assertion omits `<saml:Issuer>`.
2. **`Subject` is declared `xml:"NameID"`** — a local-name match that ignores the
   namespace, so a signed assertion omitting the real `<saml:NameID>` but carrying a
   `<NameID>` in a foreign namespace populates `Subject.NameID` from the attacker's
   element.

## 2. Exposure in this repo

**Defect 1 is doubly mitigated.** `tamper` never sets `ExpectedIDPEntityID` (no assignment
anywhere in the tree), so the branch cannot be taken; and `saml/parse.go` already wraps
`ParseResponse` in a recover barrier that turns any panic into `ErrAssertionInvalid` —
written for exactly this dereference, with tests.

**Defect 2 was not mitigated, and it is the one that matters here**: `SubjectNameID`
(`saml/assertion.go:107`) is a public surface, and applications key their `user_identities`
row on it. A signed assertion could therefore name a principal the IdP never meant — an
integrity failure, not a crash.

## 3. The fix

`ParseAssertion` now refuses an assertion that carries a `<NameID>` outside
`urn:oasis:names:tc:SAML:2.0:assertion` (`saml/nameid_ns.go`), **before** the library reads
it.

Decisions worth recording:

- **Namespace, not prefix.** The check uses `encoding/xml`'s resolved `Name.Space`, so
  `saml:NameID` and a default-`xmlns` `NameID` both pass, while `evil:NameID` and an
  unprefixed `NameID` under a foreign default namespace are refused. A prefix check would
  have been both weaker and wrong for legitimate IdPs.
- **Anywhere in the document, not only in `Subject`.** Cheap, and it removes any argument
  about which element the library would have chosen.
- **Fail closed on a foreign NameID, but not on undecodable input**: a base64 or XML error
  is left to the library, so this guard cannot become a second parse error whose wording
  differs — that would be an oracle.
- **No API change.** `SubjectNameID` keeps its signature; it simply cannot be fed a
  foreign-namespace value any more.

## 4. The CI allowance, and why it is in the same change

`govulncheck` scans code and modules, not diffs, so `main` went red the moment the advisory
was published — which blocks **every** PR, including a docs-only one. The allowance and the
fix therefore ship together: allowing the ID without the guard would be weakening the gate
to make a red build green, and the guard without the allowance could not merge at all.

`.github/workflows/ci.yml` allows **exactly `GO-2026-6909`**, in a comment that names both
halves, points at the guard and its tests, and says to drop the allowance when a fixed
release exists. Any other finding still fails the build — the filter fails on everything
not on the list.

## 5. Invariants

1. A `<NameID>` outside the assertion namespace invalidates the whole assertion.
2. `saml:NameID` and default-namespace `NameID` are unaffected — no legitimate assertion
   changes behaviour.
3. The guard never invents a new error shape for input the library would reject anyway.
4. The CI allowance is one ID, commented, and cannot grow silently: any other finding fails.

## 6. Tests and mutation proofs

`saml/nameid_ns_test.go`: six shapes (saml-prefixed, default-namespace, absent,
foreign-prefixed, foreign default, foreign elsewhere in the document) plus the
undecodable-input case.

| Mutant | Result |
|---|---|
| ignore the namespace entirely | **red** |
| treat an empty namespace as legitimate | green — **unobservable**: `encoding/xml` resolves a declared prefix or default to a URI, so `Space` is never empty for a conforming document. Kept as defence in depth and annotated rather than claimed as a proof. |

## 7. What this does not do

- It does not patch `crewjam/saml`; the real fix belongs upstream (a nil check plus
  `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`), and that is a separate PR to that
  project.
- It does not address other libraries' namespace-blind tags; the audit is this one path.
- It does not remove the allowance automatically when a fix lands — that is a human step,
  named in the CI comment.
