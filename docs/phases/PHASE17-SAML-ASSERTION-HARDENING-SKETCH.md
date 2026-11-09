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

**Defect 1 is mitigated by the recover barrier, and only by it.** This section first said
it was "doubly mitigated" because tamper never sets `ExpectedIDPEntityID`. Reading the
dependency rather than the advisory showed that reasoning is void: **`ExpectedIDPEntityID`
does not exist in `crewjam/saml` v0.5.1** (zero occurrences in the module), and
`validateAssertion` dereferences `assertion.Issuer.Value` with no nil guard
(`service_provider.go:1185`). The precondition is not narrow — it is absent, so any
**signed** assertion omitting `<Issuer>` panics. What protects us is
`saml/parse.go`'s `withParseRecover` around `ParseResponse`, which normalises the panic
into `ErrAssertionInvalid`.

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

## 6a. The size bound (review finding F-B)

The ACS path is unauthenticated, and this package parses the response **twice** before any
signature is verified: once for the namespace guard, once inside the library. Unbounded, that
is a cheap way to burn CPU. Measured on one core with the guard alone: **24 ms** for 1 MB of
base64, **117 ms** for 5 MB, **433 ms** for 20 MB — and the library then repeats the work.

So `ParseAssertion` refuses a response larger than `DefaultMaxSAMLResponseBytes` (**1 MiB**,
≈750 KiB of XML) before decoding anything, with `ErrAssertionInvalid` — the same generic
error as every other parse failure, so the bound reads as a refusal and not as a new oracle.

One mebibyte is ~25× the largest realistic assertion (10–40 KiB with a certificate chain) and
bounds the pre-signature work at tens of milliseconds. `WithMaxResponseBytes` raises or
disables it for a deployment that genuinely needs more; **zero disables it**, which restores
the unbounded behaviour deliberately rather than by accident.

## 7. What this does not do

- It does not patch `crewjam/saml`; the real fix belongs upstream (a nil check plus
  `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`), and that is a separate PR to that
  project.
- It does not address other libraries' namespace-blind tags; the audit is this one path.
- It does not remove the allowance automatically when a fix lands — that is a human step,
  named in the CI comment.

---

## Third review — the ACS URL path, one line from the guard

The namespace half of this sketch hardened `ParseAssertion`. A later review of the same
function found an unrelated defect sitting a few lines away from the code the guard calls.

`BuildProvider` validated `ACSURL` with `url.Parse` alone, and `url.Parse` accepts `"not a url"`
and `"/relative/acs"`. Those reached `buildPostFormRequest`, which built its request with
`httptest.NewRequest` — a **test** helper that panics on a target it cannot parse. Probed, not
reasoned: `BuildProvider` returned a nil error for `"not a url"`, and `ParseAssertion` then
panicked with `invalid NewRequest arguments`. A misconfigured provider took down its own login
path, per request, on the unauthenticated ACS route — and `net/http/httptest` was linked into
the shipped binary through the same call.

Fixed in three places, because any one alone leaves a hole:

1. `BuildProvider` refuses an ACS URL that is not absolute with a host. The configuration error
   now fails at `New`, which is the rule this package already follows for every other field.
2. `buildPostFormRequest` states the invariant itself (`!IsAbs() || Host == ""`) and returns an
   error. This is necessary rather than belt-and-braces: probed, `http.NewRequest` refuses
   **nothing** — it accepts `""`, `"acs"` and `"/relative/acs"` without complaint — so replacing
   the test helper removes the panic but not the bad input. Same defence-in-depth shape as the
   nil-replay check, for the same reason: a hand-built provider bypasses the constructor.
3. `net/http/httptest` is gone from `saml/`; the request is built with
   `http.NewRequestWithContext`. (`examples/*` still use it to stand up fake IdPs and fake
   servers, which is what it is for.)

Mutants, all red: the validation loosened; the invariant dropped; `httptest.NewRequest`
restored — that last one panics exactly as it did before the fix, which is how we know the
no-panic test has teeth.

**Left alone deliberately, and worth its own item:** `MetadataURL` is validated the same weak
way (parse only). Nothing dereferences it during request construction, so nothing panics, but a
relative metadata URL is equally a configuration error this gate lets through.

### The twin check that was left out (#130)

`BuildProvider` validated `acs_url` with `url.Parse` alone until #124, which accepted `"not a
url"`; that value reached the request builder, which panicked, so it was fixed. `metadata_url`
was validated the same weak way and **deliberately left alone**, with the note above: nothing
dereferences it while building a request, so there is no crash to point at.

That is the wrong standard, and this amendment says why. The refusal of a relative `acs_url`
exists because the misconfiguration must fail at `New` — the panic was the symptom, not the
reason. A relative `metadata_url` is the same configuration error wearing a quieter failure, and
"it cannot crash" only means the operator finds out later, from an IdP fetch that fails for
reasons the config does not name. So the check is added: absolute, with a host, refused at
construction with the field named in the message.

Nothing else in this sketch changes. The guard, the bound, the Allowance and the invariants stay
as written; this document is amended rather than rewritten, because the reason the item was left
out turned out to be the thing worth correcting.

---

## Fourth review — the namespace audit, beyond `NameID` (#132)

This sketch said plainly: *"It does not address other libraries' namespace-blind tags; the audit is
this one path."* This is that audit, and its answer is that `NameID` was not the only name-matched
element — nor the most consequential one.

**Method.** Read every struct tag in `crewjam/saml@v0.5.1` for the assertion tree and mark the ones
declared with a **local name only** (no namespace), because those are the fields a
foreign-namespace element populates. Then ask, per field, whether tamper or an application trusts
what it carries. Verdict per field:

| Field | Tag | Trusted by | Verdict |
|---|---|---|---|
| `Assertion.Subject` | *(none)* | the identity, and the parent of the tree below | **vulnerable** |
| `Subject.NameID` | `xml:"NameID"` | the subject identity | **vulnerable** — the original fix |
| `Subject.SubjectConfirmations` | `xml:"SubjectConfirmation"` | correlation, and the replay key | **vulnerable** |
| `SubjectConfirmation.SubjectConfirmationData` | *(none)* | `InResponseTo`, `Recipient` — correlation | **vulnerable** |
| `Assertion.AttributeStatements` / `Attribute` / `AttributeValue` | `xml:"AttributeStatement"`, `xml:"Attribute"`, `xml:"AttributeValue"` | **applications**, for JIT provisioning and authorization | **vulnerable, and the worst of them** |
| `Assertion.AuthnStatements` | `xml:"AuthnStatement"` | `AuthnInstant`, `SessionIndex` handed to applications | **vulnerable** |
| `Assertion.Issuer` | `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"` | IdP validation | **not vulnerable** — namespace-qualified, so it cannot be steered |

The last row is the one worth keeping: a guard for a field that is already safe is noise, and noise
is what teaches people to widen guards until they mean nothing. It is verified in the vendored
source, not assumed from the advisory's wording — which, as the third review found, is a habit
worth keeping.

**The fix is a set, not a second special case.** `rejectForeignNameID` now checks every element in
`localNameMatchedElements` instead of `NameID` alone, with the same rule: the element must be in
the assertion namespace, which the SAML spec requires of all of them, so a legitimate IdP is
unaffected (`saml:` prefix or default `xmlns` — both resolved by `encoding/xml`, and both asserted).

**Why attributes are the worst.** `NameID` steers *which* identity a session becomes; an attribute
steers what the application *grants* it. `ParsedAssertion.Attribute("email")` is what a JIT
provisioning hook keys on, and `AttributeValues("groups")` is what an authorization mapping reads.
A signed assertion carrying an extra foreign-namespace `AttributeStatement` can therefore add or
override values an application trusts, and slices append rather than replace — so the attack does
not even have to displace a legitimate attribute.

**What this does not do.** It does not patch the library, and it does not look at elements outside
this tree (`Response` fields, `Conditions`, `Status`) — the audit followed what tamper and its
callers trust, and `Conditions` is validated by the library against its own clock. A future audit
of the protocol-level elements is a separate item rather than a claim made here.
