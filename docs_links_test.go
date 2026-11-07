package tamper_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every local markdown link must resolve. The docs were reorganised into docs/{adrs,design,
// migrations,phases,tasks} once, and a move plus a hand-rewrite is exactly the operation that
// leaves a link pointing at a file nobody moved. This test is the guard against the next
// reorganisation, and against a link added to a document that already sat in a subfolder.
//
// It also runs over the published site in docs/, where links follow VitePress's rules: a route
// may be absolute ("/guide/tenancy"), and a relative link may omit the extension ("./tenancy").
// Those are resolved the way VitePress resolves them — which means the guard is STRONGER than
// it was, not weaker: previously every site link would have failed as a missing file.
func TestDocsLinksResolve(t *testing.T) {
	// Known dangling before the reorganisation: a JSON artifact the Phase 7 sketch mentions
	// and that has never existed in the tree. Listed rather than silently skipped so that a
	// NEW dangling link cannot hide behind the same allowance.
	allowed := map[string]bool{"phase7-issues.json": true}

	// Build-generated pages: they exist in the deployed site but not in the tree, because the
	// site's changelog is GENERATED from CHANGELOG.md by scripts/sync-changelog.mjs rather than
	// copied — two copies is two things to forget. Named individually so a typo in a link to
	// any of them still fails: the guard knows this one page, not a category of pages.
	generated := map[string]bool{"changelog.md": true}

	link := regexp.MustCompile(`\]\(([^)#\s]+)(#[^)]*)?\)`)
	checked := 0
	seen := 0
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "node_modules" || info.Name() == ".vitepress" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		seen++
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range link.FindAllStringSubmatch(string(body), -1) {
			target := m[1]
			if strings.HasPrefix(target, "http") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			checked++
			if allowed[target] || generated[filepath.Base(target)+".md"] {
				continue
			}
			resolved := resolveDocLink(path, target)
			if _, statErr := os.Stat(resolved); statErr != nil {
				t.Errorf("%s: link %q does not resolve (looked for %s)", path, target, resolved)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// A floor derived from the tree, not a round number: the repository holds ~34 markdown
	// files and ~44 local links, so a walk that sees fewer than 30 files or 30 links is not
	// looking at the documents. (The first version of this test guessed 50 links and failed
	// on a correct walk — the guard must be checked against the tree, like any other count.)
	if seen < 30 {
		t.Fatalf("walked only %d markdown files — expected the docs/ tree and the root files", seen)
	}
	if checked < 30 {
		t.Fatalf("checked only %d links — the walk is not seeing the documents", checked)
	}
}

// resolveDocLink turns a link in `page` into the file it must exist as.
//
// Two link shapes, and the site's config is the reason both are here:
//   - an absolute route ("/guide/tenancy"), which VitePress resolves inside `docs/` after
//     stripping the configured base;
//   - a relative path that may omit the extension ("./tenancy"), which VitePress resolves to
//     `tenancy.md` or `tenancy/index.md`.
//
// A caller that gets a non-existent path back reports it, so the failure message names the
// file that was looked for rather than the raw link.
func resolveDocLink(page, target string) string {
	base := filepath.Dir(page)
	if strings.HasPrefix(target, "/") {
		base = "docs"
		target = strings.TrimPrefix(strings.TrimPrefix(target, "/tamper/"), "/")
	}
	for _, candidate := range []string{target, target + ".md", filepath.Join(target, "index.md")} {
		if candidate == "" {
			continue
		}
		resolved := filepath.Join(base, candidate)
		if _, err := os.Stat(resolved); err == nil {
			return resolved
		}
	}
	return filepath.Join(base, target)
}

// The version the site advertises and the version the docs tell people to install are the same
// number, and they are the newest RELEASED one in CHANGELOG.md.
//
// This exists because the site's version is generated while the two pins below are written by
// hand, and the release procedure is exactly when a hand-written pin goes stale: cutting
// 0.13.0 adds a heading, and without this test the install line keeps recommending 0.12.0 to
// everyone who reads it. It fails on the release PR, which is the moment to fix it.
func TestDocsVersionPinsMatchTheChangelog(t *testing.T) {
	changelog, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	m := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindSubmatch(changelog)
	if m == nil {
		t.Fatal("CHANGELOG.md has no released version heading (## [x.y.z])")
	}
	version := string(m[1])

	for _, page := range []string{"README.md", "docs/guide/installation.md"} {
		body, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("read %s: %v", page, err)
		}
		want := "tamper@v" + version
		if !strings.Contains(string(body), want) {
			t.Errorf("%s does not pin %s — the newest released version in CHANGELOG.md is v%s, "+
				"and a stale pin recommends a version that is not the latest", page, want, version)
		}
	}
}
