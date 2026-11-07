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
func TestDocsLinksResolve(t *testing.T) {
	// Known dangling before the reorganisation: a JSON artifact the Phase 7 sketch mentions
	// and that has never existed in the tree. Listed rather than silently skipped so that a
	// NEW dangling link cannot hide behind the same allowance.
	allowed := map[string]bool{"phase7-issues.json": true}

	link := regexp.MustCompile(`\]\(([^)#\s]+)(#[^)]*)?\)`)
	checked := 0
	seen := 0
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "node_modules" {
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
			if allowed[target] {
				continue
			}
			resolved := filepath.Join(filepath.Dir(path), target)
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
