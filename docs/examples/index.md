# The examples, and what each proves

Every example is a runnable program with a specific claim it demonstrates. They are the
fastest way to see how the pieces fit, and they are where several invariants were first
found to be false.

| Example | Claim it proves |
|---|---|
| [`quickstart`](https://github.com/suryakencana007/tamper/tree/main/examples/quickstart) | One file, one tenant: register, log in, `/me`, TOTP, refresh — with the public/authenticated split |
| [`multitenant`](https://github.com/suryakencana007/tamper/tree/main/examples/multitenant) | **One surface serves every tenant.** A tenant created at runtime has routes with no restart, and one browser holds a live session per tenant (the path separates the cookie jars) |
| [`tenanthierarchy`](https://github.com/suryakencana007/tamper/tree/main/examples/tenanthierarchy) | Plans, entitlements and IdP configuration **inherit** down a parentage chain, while **authorization does not** — bindings stay per tenant |
| [`federation`](https://github.com/suryakencana007/tamper/tree/main/examples/federation) | OIDC login against a stand-in IdP, with the app's own linking decision (JIT provisioning or refusal) |
| [`scim`](https://github.com/suryakencana007/tamper/tree/main/examples/scim) | A SCIM 2.0 server over an in-memory store: filters, PATCH, groups — behind a machine-credential gate |
| [`discord`](https://github.com/suryakencana007/tamper/tree/main/examples/discord) | An OAuth2 social provider end to end, including the state and PKCE plumbing |

## Running them

```sh
git clone https://github.com/suryakencana007/tamper
cd tamper/examples/multitenant
go run .
```

Each example's `doc.go` and comments explain the wiring as it happens: the examples double as
the reference for *why* a call is made, not just *which* one. Where the old shape was
replaced, the comment usually says what the old shape got wrong.

## What to read, in order

1. **`quickstart`** — the smallest complete picture. Start here.
2. **`multitenant`** — the tenant path. The lesson is in `main.go`: one template prefix,
   one resolver, and the pin every route reads.
3. **`tenanthierarchy`** — what inherits and what deliberately does not.
4. **`scim`** — machine credentials, and the difference between a tenant credential and a
   platform one.

## The examples are load-bearing

They are not illustrations kept in sync by hand. Changes to the library have repeatedly been
caught by an example failing — a dropped tenant, a gate that stopped being mounted, a
credential that reached the wrong surface — which is why each example carries tests for the
thing it demonstrates, not only a `main.go` that compiles.
