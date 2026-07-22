# Tamper Repo-Split — design sketch

> Status: **design sketch, NOT started.** This is the procedure + the decisions
> to make *when* the split is executed. It is the deferred successor to the
> Phase 6 standalone-packaging milestone (see
> [`PHASE6-STANDALONE-PACKAGING-SKETCH.md`](./PHASE6-STANDALONE-PACKAGING-SKETCH.md)),
> named there as the one remaining forward milestone.
>
> Nothing here should be executed without a deliberate go-ahead — the split is
> mechanical but touches two repos and the release Docker build, and it trades
> away the monorepo's atomic cross-repo changes.

## What "repo split" means

Move Tamper out of the Barista monorepo into its **own git repository**,
`github.com/suryakencana007/tamper`, with a clean module path. Two things change,
bundled but distinct:

1. **Module rename** (breaking): `github.com/suryakencana007/barista/packages/tamper`
   → `github.com/suryakencana007/tamper`. Rewrites every internal import in
   Tamper **and** Barista's `require`/`replace`.
2. **Physical move**: the `packages/tamper/` files become a standalone repo
   (with history preserved), its own CI, README front page, issues, releases,
   and tags.

**The model already exists in this codebase: Espresso.** Espresso lives in its
own repo (`github.com/suryakencana007/espresso/v2`) and Barista consumes it as a
normal versioned dependency (`require …/espresso/v2 v2.4.0`), developed in
tandem. A Tamper split makes Tamper a second Espresso.

## Current state (as of Barista v1.18.0 / tamper v0.1.0)

| Fact | Value |
|---|---|
| Module path | `github.com/suryakencana007/barista/packages/tamper` |
| Location | `packages/tamper/` |
| Tamper's own `.go` files (internal imports to rewrite) | **143** |
| Barista files importing the tamper path (consumer rewrite) | **56** (handler ×17, middleware ×9, auth/authz/identity/idp/scimstore/service/audit/cmd) |
| Workspace | `go.work` `use ./packages/tamper` |
| Barista `go.mod` | `require …/packages/tamper v0.0.0-…` + `replace …/packages/tamper => ../../packages/tamper` |
| Docker build | `deploy/Dockerfile` `COPY packages/tamper/…` (tamper is local source) |
| CI | `ci.yml` runs `tamper:lint`, `tamper:vet`, `tamper:test` |
| moon | `.moon/workspace.yml` project `tamper: 'packages/tamper'` |
| Tag | `packages/tamper/v0.1.0` (nested subdir tag) |

## The decision it hinges on

The split's payoff is a **clean import path external projects adopt without
pulling the whole Barista repo**, plus a standalone product identity (own front
page, releases, issues). That payoff is **not being realized yet**: Barista is
currently the only consumer, and the repo is private (nobody outside can
`go get` it anyway).

- The monorepo was the **right call during the extraction** (Phases 0–6 — every
  "lift X from Barista into Tamper" was a single atomic PR).
- Now that the extraction is **done**, the need for atomic cross-repo changes
  drops, so the split is more palatable than it was.
- **Gate:** do it when Tamper has a consumer beyond Barista, or when you want it
  public / standalone. Until then, deferring costs nothing — `v0.1.0` already
  works for the rare external `go get`, and atomic co-development stays free.

## Procedure

Two phases, ordered so **Barista never breaks in between**: stand up the new
repo first (Barista untouched, still building via the existing `replace`), then
flip Barista over in a single PR.

### Phase A — stand up `github.com/suryakencana007/tamper` (Barista unaffected)

1. **Extract `packages/tamper/` with its history.** On a fresh clone:
   ```bash
   git filter-repo --path packages/tamper/ --path-rename packages/tamper/:
   ```
   Rewrites the clone so Tamper's content is the repo *root*, keeping only its
   history. (`git subtree split --prefix=packages/tamper` also works; filter-repo
   is cleaner because it rewrites paths to root.)

2. **Rename the module + rewrite the 143 internal imports.**
   ```bash
   # go.mod:  module github.com/suryakencana007/tamper
   grep -rl 'suryakencana007/barista/packages/tamper' --include='*.go' . \
     | xargs sed -i 's#suryakencana007/barista/packages/tamper#suryakencana007/tamper#g'
   go build ./... && go test -race ./...   # confirms the rewrite is complete
   ```
   Catches the subpackage paths too (`…/packages/tamper/crypto` → `…/tamper/crypto`).

3. **Give it its own scaffolding.** `README.md`, `TAMPER-DESIGN.md`, `sqlc.yaml`,
   the `PHASE*` sketches, and `examples/` all move with it. Add a CI workflow
   (`go vet` / `go test -race` / `golangci-lint` + the sqlc regen check),
   copying over the `.golangci.yaml` rule set. Drop or slim the `moon.yml`
   (a standalone repo may not need moon).

4. **Create the GitHub repo, push, tag.** Because the module *path* changed, Go
   treats this as a **brand-new module** — it starts its own version line at
   `v0.1.0` (or `v0.2.0` to signal "post-split"). The old
   `packages/tamper/v0.1.0` tag stays harmlessly in Barista's history. **No
   external migration burden — there are no external consumers.**

### Phase B — flip Barista over (one PR, after A is live + green)

5. `git rm -r packages/tamper/`.
6. **`apps/barista/go.mod`:** delete the pseudo-version `require` + the
   `replace … => ../../packages/tamper`; add
   `require github.com/suryakencana007/tamper vX.Y.Z` (plus, optionally,
   `replace github.com/suryakencana007/tamper => ../tamper` for local co-dev —
   see below).
7. **Sweep the 56 Barista files' imports** with the same `sed` as step 2, then
   `go -C apps/barista build ./...`.
8. **`go.work`:** drop `./packages/tamper` (optionally add a sibling `./tamper`
   `use` for local dev).
9. **Remove Tamper from the monorepo scaffolding:** the `tamper:*` steps in
   `ci.yml`, the `tamper:` project in `.moon/workspace.yml`.
10. **`deploy/Dockerfile`:** remove the `COPY packages/tamper/…` lines — and
    rewire the build's dependency resolution (the fiddly part, below).
11. **Docs:** update `CLAUDE.md`, `AGENTS.md`, `packages/tamper/TAMPER-DESIGN.md`
    references to the new home.
12. **Verify:** `go -C apps/barista build ./...`, `GOWORK=off go build`, the full
    `-race` suite, and the release Docker build end-to-end.

## The one genuinely fiddly part — the Docker build 🔴

Steps 1–12 are mostly mechanical. **The real work is `deploy/Dockerfile`.**
Today it `COPY`s the tamper source because tamper is local. After the split,
`go mod download` must **fetch** tamper from GitHub — and since both repos are
**private**, the build needs auth. Two viable approaches:

- **(a) Versioned fetch (the Espresso model; cleanest long-term).**
  `GOPRIVATE=github.com/suryakencana007/*` + a GitHub token wired into the
  builder stage (`git config --global url."https://<token>@github.com/".insteadOf
  "https://github.com/"`), and Barista pins a real tamper version. Downside:
  a token flows into the build; the release pipeline must inject it.
- **(b) Keep a `replace` + multi-repo checkout.** CI checks out both repos, the
  Docker build context includes a sibling `tamper/`, and `go.mod` keeps
  `replace … => ../tamper`. No fetch auth, but the build context + CI get more
  complex, and it partly defeats "clean versioned dependency."

This auth plumbing + re-validating the release pipeline end-to-end (mind the
v1.18.0 release-gauntlet history — see `AGENTS.md`) is where the time and risk
actually live, not the file moves.

## Co-development after the split

The monorepo gives **atomic** cross-repo changes for free. After the split, a
change spanning both repos becomes: change Tamper → tag it → bump Barista's
require. Mitigations:

- **Local dev:** keep `replace github.com/suryakencana007/tamper => ../tamper`
  in Barista's `go.mod` (both repos checked out side by side) so day-to-day work
  stays atomic-ish.
- **Releases:** the `replace` must NOT decide the shipped version — the release
  build resolves a real pinned tag (approach (a) above), or the replace is
  gated behind a build tag / removed for release. This is the same tandem
  friction Espresso already lives with (`ESPRESSO_USAGE.md` tracks it).

## Effort

- **Mechanical:** ~1 focused day (extract, rename, two import sweeps, scaffolding).
- **Fiddly:** the private-repo Docker build auth + release re-validation — budget
  care here.
- **Ongoing:** two-PR + version-bump friction for cross-repo changes (hidden by a
  local `replace` during dev).

Net: not a big or risky refactor **except** the Docker/private-fetch step.

## Open decisions (resolve at execution time)

1. **Version:** start the new repo at `v0.1.0` or `v0.2.0` (signal the path
   change)?
2. **History tool:** `git filter-repo` (preferred) vs `git subtree split`.
3. **Docker dependency resolution:** approach (a) versioned-fetch-with-token vs
   (b) replace-with-sibling-checkout.
4. **Co-dev mode:** keep a local `replace` in Barista's `go.mod`, or go
   fully-versioned immediately.
5. **Public or private:** if the whole point is external adoption, does the new
   repo go public (which also unlocks pkg.go.dev + a proxy-served `go get`)?

## Non-goals

- No behavior change — this is a move + rename, not a code change. Byte-identical
  Tamper.
- Not to be done until there's a consumer beyond Barista or a decision to make
  Tamper public/standalone (see "The decision it hinges on").

## Execution safety

Do **Phase A entirely first** (new repo green on its own, Barista still building
via the existing `replace`), then a **single Barista PR** for Phase B,
adversarially reviewed like the other slices. The gap between the two phases is
safe — Barista keeps compiling against the in-tree `packages/tamper` until
Phase B flips it.

---

## Hand-off execution checklist

A copy-pasteable checklist for whoever executes the split. Read the sections
above first (especially "The one genuinely fiddly part"). Commands assume the
final path `github.com/suryakencana007/tamper`; adjust if the name changes.

### 0. Pre-flight — decide + provision

- [ ] **Decide: public or private** new repo. Public → no auth needed anywhere
      (and `go get` + pkg.go.dev work for free). Private → a token is required
      (see step 0d). This choice drives the whole Docker section.
- [ ] **Decide: version** to cut in the new repo — `v0.1.0` (fresh) or `v0.2.0`
      (signal "post-split"). New module path = new version line either way.
- [ ] **Decide: Docker dependency approach** — (a) versioned fetch with a token,
      or (b) keep a `replace` + sibling checkout in the build context.
- [ ] **Decide: co-dev mode** — keep a local `replace` in Barista's `go.mod`, or
      go fully-versioned immediately.
- [ ] **Install `git filter-repo`** (`pip install git-filter-repo`, or Homebrew).
      Not bundled with git.
- [ ] **Confirm rights** to create a repo under `suryakencana007` (or the org).
- [ ] **(private only) Provision a GitHub token / deploy key** with read on the
      new repo, and note where it goes: CI secrets + the release Docker build.
- [ ] **Start from a clean `main`**, no in-flight `packages/tamper` changes.

### Phase A — stand up the new repo (Barista untouched)

- [ ] Fresh clone of Barista into a scratch dir.
- [ ] Extract with history:
      `git filter-repo --path packages/tamper/ --path-rename packages/tamper/:`
- [ ] Rename the module: `go.mod` → `module github.com/suryakencana007/tamper`.
- [ ] Sweep the **143** internal imports:
      `grep -rl 'suryakencana007/barista/packages/tamper' --include='*.go' . | xargs sed -i 's#suryakencana007/barista/packages/tamper#suryakencana007/tamper#g'`
- [ ] `go build ./...` **green**.
- [ ] `go test -race ./...` **green** (the parity proof — no behavior change).
- [ ] Confirm the moved scaffolding is coherent: `README.md`, `TAMPER-DESIGN.md`,
      the `PHASE*`/`REPO-SPLIT` sketches, `sqlc.yaml`, `examples/`.
- [ ] Add the new repo's own CI (`go vet` / `go test -race` / `golangci-lint`,
      + the sqlc regen check); copy the repo-root `.golangci.yaml` rules.
- [ ] Drop or slim `moon.yml` (a standalone repo may not need moon).
- [ ] Create the GitHub repo (public/private per step 0a), push.
- [ ] Tag `vX.Y.Z` and push the tag.
- [ ] Verify resolution from a throwaway module:
      `GOPRIVATE=github.com/suryakencana007/* go get github.com/suryakencana007/tamper@vX.Y.Z`
      (public: no GOPRIVATE/token needed).

### Phase B — flip Barista (one PR)

- [ ] Branch off `main`.
- [ ] `git rm -r packages/tamper/`.
- [ ] `apps/barista/go.mod`: delete the pseudo-version `require` + the
      `replace … => ../../packages/tamper`; add
      `require github.com/suryakencana007/tamper vX.Y.Z` (+ optional
      `replace … => ../tamper` if co-dev mode = local replace).
- [ ] Sweep the **56** Barista importers (same `sed` as Phase A, scoped to
      `apps/barista`).
- [ ] `go.work`: remove `./packages/tamper` (optionally add `./tamper`).
- [ ] Remove the `tamper:*` steps from `.github/workflows/ci.yml`
      (`tamper:lint`, `tamper:vet`, `tamper:test`).
- [ ] Remove the `tamper:` project from `.moon/workspace.yml`.
- [ ] `deploy/Dockerfile`: remove the `COPY packages/tamper/…` lines and wire the
      chosen dep approach:
      - (a) versioned fetch: `ENV GOPRIVATE=github.com/suryakencana007/*` +
        inject the token via a build secret +
        `git config --global url."https://<token>@github.com/".insteadOf "https://github.com/"` in the builder stage.
      - (b) replace + sibling: check out both repos in CI, add `tamper/` to the
        build context, keep the `replace` in `go.mod`.
- [ ] Update docs: `CLAUDE.md`, `AGENTS.md`, `packages/tamper/TAMPER-DESIGN.md`
      references to the new home.
- [ ] `go -C apps/barista build ./...` **green**.
- [ ] `GOWORK=off go build ./...` **green** (the no-workspace path the image uses).
- [ ] Full `-race` suite **green** (`moon run barista:ci` + `barista:test-postgres`).
- [ ] **Build the release image locally** (`moon run barista:docker-build` or the
      Dockerfile directly) — the real proof the fetch/replace resolves in-container.
- [ ] Adversarial review of the PR (as with every slice).
- [ ] Merge; confirm `ci.yml` **green** on `main`.

### Post-split

- [ ] Dry-run or cut a Barista patch release to prove the release pipeline works
      with the fetched/replaced tamper (mind the release-gauntlet history —
      `AGENTS.md` §Release process).
- [ ] Confirm the new tamper repo's CI is green and its tag resolves externally.
- [ ] `AGENTS.md`: move the repo-split from "deferred" to "recently done".

### Rollback

Phase A is non-destructive (Barista untouched). If Phase B's Docker/release step
fails, **revert the single Phase-B PR** — the in-tree `packages/tamper` is
preserved in git history until that PR merges, so Barista returns to the working
monorepo state immediately. Fix the Docker plumbing, re-open.
