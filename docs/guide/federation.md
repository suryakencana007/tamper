# Federation: OIDC and SAML

Both protocols are *per tenant*. A tenant can have its own IdP, and a tenant that has none
inherits its nearest ancestor's — which is what makes "this customer is on their own Entra
tenant, everyone else uses ours" configurable rather than special-cased.

| Package | Role |
|---|---|
| `oidc` | Relying party: discovery, PKCE, ID-token verification, provider manager |
| `saml` | Service provider: AuthnRequest, metadata, assertion parsing, replay defence |

Providers are store-backed, so they can be created at runtime without a restart, and their
client secrets are sealed with the KEK keyset from `crypto` rather than stored in clear.

## SAML, in more detail

```go
provider, err := saml.BuildProvider(cfg, idpMetadata, replayStore,
    saml.WithMaxResponseBytes(1<<20),   // the default; raise or remove it deliberately
)
```

`BuildProvider` refuses a configuration that cannot work, at construction rather than on
the request path:

- an **ACS URL that is not absolute** is refused, because a relative one used to reach the
  request builder and panic there;
- a missing **replay store** is refused: assertions are single-use, and the ledger is the
  thing that makes that true.

Parsing an assertion is deliberately strict about the things an attacker controls:

- **A `<NameID>` outside the SAML assertion namespace refuses the whole assertion**
  (GO-2026-6909). `crewjam/saml` matches that element by local name, so without the guard a
  signed assertion could carry `<NameID>` in a foreign namespace and steer the identity your
  application keys its user rows on.
- **Responses are bounded at 1 MiB** (`DefaultMaxSAMLResponseBytes`). The ACS path is
  unauthenticated and the body is parsed before any signature is verified, so an unbounded
  response is a cheap way to burn CPU.
- The refusal is the **same generic error** as any other parse failure, so the bound cannot
  become an oracle that tells a caller which check it hit.

## Assertions are single-use

An assertion is a bearer credential for a session. tamper consumes each one exactly once
against a ledger you supply:

```go
saml.NewMemAssertionReplayStore()   // one process
// or your own shared store for several replicas
```

A ledger outage returns `ErrReplayStoreUnavailable` → **503, never a silent accept**. A
consumed assertion returns `ErrAssertionReplayed`.

## What tamper hands back

```go
assertion, err := provider.ParseAssertion(ctx, samlResponse, relayState, expectedRequestID)
assertion.NameID()                    // the subject identity
assertion.Attribute("email")           // attribute lookup, Name or FriendlyName
assertion.AttributeValues("groups")    // every value, multi-element or comma-separated
```

Your application decides what to do with those: link to an existing user, provision a new
one, or refuse. That decision is policy, and policy lives in your app —

```go
// The link step is an app hook, so "unknown user" can mean JIT provisioning
// or a refusal, depending on the tenant.
hooks := tamperespresso.FederationHooks{ /* … */ }
```

## The flows that are not login

`espresso` also mounts the pieces a federation needs around the login leg: metadata
documents, the ACS endpoint, and the AuthnRequest URL (with step-up support, so an IdP can
be asked for a stronger authentication than the last one).

Every federation route is tenant-scoped like the rest of the surface: the tenant is resolved
from the request, and the session it produces carries that tenant.
