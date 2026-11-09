package tamper_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDocsSnippetsCompile compiles the Go blocks in the documentation.
//
// It exists because a page that teaches a wrong signature is worse than a page with no code: the
// first draft of the quickstart page invented `identity.New(cfg, store, jwtSvc)`, and a compiler
// would have refused it before review did.
//
// Two conventions, and the difference matters:
//
//	```go          MUST compile, so it must be a complete file — package clause and imports
//	               included. That is also what makes it copy-pasteable.
//	```go ignore    a fragment: it references identifiers the page does not define. Explicit,
//	               counted, and asserted, so an exemption cannot be taken by omission.
//
// A fenced block marked `go` without a package clause fails with the instruction rather than
// silently joining the fragments.
func TestDocsSnippetsCompile(t *testing.T) {
	// Every fragment in the guide and example pages, marked explicitly. Pinned: adding one
	// without converting a snippet is a decision, and this is where it has to be made.
	//
	// The number is COUNTED, not remembered — the first version of this test pinned 27, from
	// counting a narrower set of files, and failed on a correct walk. Same defect as the
	// PROOF-SWEEP heading that said 14 over 20 rows, which is why that one is a test too.
	const wantExempt = 29
	// The worked examples in guide/tenancy.md. A floor rather than an exact count, so adding
	// more compiled snippets is encouraged and removing the last one is not.
	const minCompiled = 2

	fence := regexp.MustCompile("(?ms)^```go( ignore)?[ \t]*\n(.*?)^```[ \t]*$")

	var compiled, exempt []struct{ page, code string }
	files := docPages(t)
	for _, page := range files {
		body, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("read %s: %v", page, err)
		}
		for _, m := range fence.FindAllStringSubmatch(string(body), -1) {
			item := struct{ page, code string }{page, m[2]}
			if strings.TrimSpace(m[1]) == "ignore" {
				exempt = append(exempt, item)
				continue
			}
			if !strings.Contains(m[2], "package ") {
				t.Errorf("%s: a ```go block has no package clause — mark it ```go ignore if it is a "+
					"fragment, or make it a complete file so this test can compile it", page)
				continue
			}
			compiled = append(compiled, item)
		}
	}

	if len(exempt) != wantExempt {
		t.Errorf("found %d exempt (```go ignore) blocks, the test pins %d — if a fragment was added, "+
			"say so here; if one was converted, lower the pin. A count that drifts silently is how "+
			"an exemption becomes a blanket", len(exempt), wantExempt)
	}
	if len(compiled) < minCompiled {
		t.Fatalf("found %d compiled blocks, the test requires at least %d — the snippets that were "+
			"converted must stay converted", len(compiled), minCompiled)
	}
	if len(compiled) == 0 {
		return // nothing to build; the counts above are the whole test
	}

	// Build them inside the module rather than in a temp module, so the imports a snippet
	// writes are resolved exactly as a reader's would be. One directory per snippet: two pages
	// may legitimately declare the same helper name.
	// NOT a dot-directory, and that is not cosmetic: `go build ./.snippetcheck/...` matches
	// nothing, because Go's package patterns skip directories whose names begin with a dot.
	// The first version of this test therefore "compiled" the snippets by building zero
	// packages and passing — a guard that could not fail, in the test written to stop
	// documentation from drifting. Found by running the mutant that breaks a snippet's API call
	// and watching it survive.
	root := filepath.Join("snippetcheck_tmp")
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("clean %s: %v", root, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	for i, item := range compiled {
		dir := filepath.Join(root, "s"+strconvItoa(i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		source := "// Code block %d, extracted from %s by docs_snippet_compile_test.go.\n" +
			"// Do not edit here: edit the page.\n" + item.code
		if err := os.WriteFile(filepath.Join(dir, "snippet.go"), []byte(source), 0o644); err != nil {
			t.Fatalf("write snippet: %v", err)
		}
	}

	// Each package is named explicitly rather than matched with ./... , so a path that does not
	// exist is an error instead of a pattern that resolves to nothing.
	args := []string{"build"}
	for i := range compiled {
		args = append(args, "./"+filepath.Join(root, "s"+strconvItoa(i)))
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("a documented snippet does not compile — the page teaches code that would not run:\n%s",
			strings.TrimSpace(string(out)))
	}
	t.Logf("%d compiled snippets, %d exempt fragments", len(compiled), len(exempt))
}

// docPages returns the pages whose code is meant for a reader: the published site's guide and
// examples, plus the front page. The design record is excluded — its code snippets are history,
// and the working record is not documentation at all.
func docPages(t *testing.T) []string {
	t.Helper()
	var pages []string
	for _, dir := range []string{"docs", "docs/guide", "docs/examples"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			pages = append(pages, filepath.Join(dir, e.Name()))
		}
	}
	if len(pages) < 5 {
		t.Fatalf("only %d pages found — the walk is not seeing the documentation", len(pages))
	}
	return pages
}

func strconvItoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
