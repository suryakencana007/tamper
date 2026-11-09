package tamper_test

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestAPIReferenceNamesEveryPackage keeps docs/api/index.md honest.
//
// The page is generated from `go doc -short`, and a generated page that nothing checks becomes a
// page that describes a previous version of the library — quietly, which is the failure mode this
// repository keeps finding. So the test regenerates the symbol names and compares them with what
// the page lists: a rename, a removal or a new exported name fails here, and the message says to
// regenerate rather than to edit by hand.
//
// Only NAMES are compared, not signatures. Signatures differ in formatting between Go versions,
// and a guard that goes red for cosmetic reasons is a guard people learn to ignore.
func TestAPIReferenceNamesEveryPackage(t *testing.T) {
	page, err := os.ReadFile("docs/api/index.md")
	if err != nil {
		t.Fatalf("read the API reference: %v", err)
	}
	sections := parseReferenceSections(string(page))
	if len(sections) < 8 {
		t.Fatalf("parsed %d package sections — the page shape changed and this test is no longer "+
			"reading it", len(sections))
	}

	for pkg, listed := range sections {
		docd, err := docNames(pkg)
		if err != nil {
			t.Errorf("%s: %v", pkg, err)
			continue
		}
		if diff := diffNames(docd, listed); diff != "" {
			t.Errorf("docs/api/index.md is out of date for %s: %s\nRegenerate the page from "+
				"`go doc -short ./%s` rather than editing it by hand", pkg, diff, pkg)
		}
	}

	// And the other direction: a new exported package must be added to the page.
	for _, pkg := range publicPackages(t) {
		if _, ok := sections[pkg]; !ok {
			t.Errorf("package %q is exported and missing from the API reference — add a section "+
				"(which is the point: a new surface should be a decision, not an omission)", pkg)
		}
	}
}

var sectionRe = regexp.MustCompile("(?ms)^## `([a-z0-9/]+)`\n.*?^```text\n(.*?)^```")

func parseReferenceSections(page string) map[string][]string {
	sections := map[string][]string{}
	for _, m := range sectionRe.FindAllStringSubmatch(page, -1) {
		var names []string
		for _, line := range strings.Split(m[2], "\n") {
			if n := symbolName(line); n != "" {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		sections[m[1]] = names
	}
	return sections
}

// symbolName pulls the identifier out of a `go doc -short` line, for both plain declarations and
// methods: "func Ancestors(…)" -> Ancestors, "type ID struct{…}" -> ID, "func (id ID) Valid()" ->
// Valid.
func symbolName(line string) string {
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "func ("):
		rest := line[strings.Index(line, ")")+1:]
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			return strings.TrimSuffix(fields[0], "(")
		}
	case strings.HasPrefix(line, "func "), strings.HasPrefix(line, "type "), strings.HasPrefix(line, "var "):
		fields := strings.Fields(line)
		if len(fields) > 1 {
			return strings.TrimSuffix(strings.SplitN(fields[1], "[", 2)[0], "(")
		}
	case strings.HasPrefix(line, "const "):
		fields := strings.Fields(line)
		if len(fields) > 1 {
			return fields[1]
		}
	}
	return ""
}

func docNames(pkg string) ([]string, error) {
	out, err := exec.Command("go", "doc", "-short", "./"+pkg).Output()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if n := symbolName(line); n != "" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

func diffNames(want, got []string) string {
	in := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	var missing, extra []string
	for _, w := range want {
		if !in(got, w) {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if !in(want, g) {
			extra = append(extra, g)
		}
	}
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "missing from the page: "+strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		parts = append(parts, "listed but no longer exported: "+strings.Join(extra, ", "))
	}
	return strings.Join(parts, "; ")
}

// publicPackages lists the packages a reader can import: nothing under internal/, nothing that
// exists only for tests or examples.
func publicPackages(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		rel := strings.TrimPrefix(line, "github.com/suryakencana007/tamper")
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" || rel == "tamper" || strings.Contains(rel, "internal/") ||
			strings.HasPrefix(rel, "examples") || strings.HasSuffix(rel, "tenanttest") {
			continue
		}
		if _, err := os.Stat(rel); err != nil {
			continue
		}
		pkgs = append(pkgs, rel)
	}
	return pkgs
}
