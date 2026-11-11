package tamper_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The vulnerability gate has to be TESTED, because the version of it that lived in ci.yml was green
// for every run while the scanner reported findings: it parsed govulncheck's output line by line,
// and that output is a stream of pretty-printed objects spanning many lines. Every line failed to
// parse, every failure was skipped, and the step passed. This test is what makes that impossible to
// reintroduce: each shape below is fed to the gate and the exit code is asserted.
func TestVulnGate(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed; the gate is exercised by CI where it is required")
	}

	fresh := time.Now().UTC().Add(-2 * time.Hour).Format("2006-01-02T15:04:05Z")
	stale := time.Now().UTC().Add(-90 * 24 * time.Hour).Format("2006-01-02T15:04:05Z")

	cases := []struct {
		name     string
		report   string
		wantExit int
		wantMsg  string
	}{
		{
			name: "a symbol-level finding fails the gate — the case the old parser missed",
			report: stream(
				config(fresh),
				sbom(),
				// Pretty-printed across several lines, exactly as govulncheck emits it: the old
				// per-line parser could not read this and passed. A NON-allow-listed advisory,
				// because the point of this case is the shape, not the exemption.
				finding("GO-2026-9999", true),
			),
			wantExit: 1,
			wantMsg:  "GO-2026-9999",
		},
		{
			name: "a different finding fails it too",
			report: stream(
				config(fresh), sbom(), finding("GO-2026-1234", true),
			),
			wantExit: 1,
			wantMsg:  "GO-2026-1234",
		},
		{
			name:     "only the pinned advisory, symbol-level: passes and says so",
			report:   stream(config(fresh), sbom(), finding("GO-2026-6909", true)),
			wantExit: 0,
			wantMsg:  "allow-listed",
		},
		{
			name:     "a module-level advisory does not block a release",
			report:   stream(config(fresh), sbom(), finding("GO-2026-5932", false)),
			wantExit: 0,
			wantMsg:  "allow-listed",
		},
		{
			// The shape that made me get reachability wrong: a vulnerable symbol in a dependency
			// DOES carry a trace, so "has a trace" is not the test — the trace has to pass through
			// our module. With a trace length check, this would have blocked the release.
			name:     "a finding whose trace never enters our code does not block a release",
			report:   stream(config(fresh), sbom(), findingInDependency("GO-2026-5932")),
			wantExit: 0,
			wantMsg:  "allow-listed",
		},
		{
			name:     "no config message: the scan described nothing",
			report:   stream(sbom(), finding("GO-2026-1234", true)),
			wantExit: 2,
			wantMsg:  "no config message",
		},
		{
			name:     "a stale database reads like a clean scan, so it fails",
			report:   stream(config(stale), sbom()),
			wantExit: 2,
			wantMsg:  "database is",
		},
		{
			name:     "an unparseable report fails rather than passing",
			report:   "{not json",
			wantExit: 2,
			wantMsg:  "not parseable",
		},
		{
			name:     "a clean scan passes",
			report:   stream(config(fresh), sbom()),
			wantExit: 0,
			wantMsg:  "no vulnerabilities in called code",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "report.json")
			if err := os.WriteFile(path, []byte(tc.report), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			cmd := exec.Command("python3", "scripts/vuln_gate.py", path)
			out, err := cmd.CombinedOutput()

			got := 0
			var exitErr *exec.ExitError
			if err != nil {
				if !asExitError(err, &exitErr) {
					t.Fatalf("run gate: %v (%s)", err, out)
				}
				got = exitErr.ExitCode()
			}
			if got != tc.wantExit {
				t.Fatalf("exit = %d, want %d\noutput:\n%s", got, tc.wantExit, out)
			}
			if !strings.Contains(string(out), tc.wantMsg) {
				t.Errorf("output does not mention %q:\n%s", tc.wantMsg, out)
			}
		})
	}
}

// The allow-list must contain only advisories whose reason is recorded, and the reason lives next to
// it. This is the guard against an allow-list growing quietly: the previous one lingered for two
// releases carrying a claim that had already been disproven.
func TestVulnGateAllowListIsDocumented(t *testing.T) {
	body, err := os.ReadFile("scripts/vuln_gate.py")
	if err != nil {
		t.Fatalf("read gate: %v", err)
	}
	src := string(body)
	start := strings.Index(src, "ALLOW = {")
	end := strings.Index(src[start:], "}")
	allow := src[start : start+end+1]

	ids := regexp.MustCompile(`GO-\d{4}-\d+`).FindAllString(allow, -1)
	if len(ids) == 0 {
		t.Fatal("parsed no advisories out of ALLOW — this test is not reading the allow-list")
	}
	for _, id := range ids {
		// The reason is written as "GO-…: crewjam/saml through …" in the comment above ALLOW.
		if !strings.Contains(src, id+":") {
			t.Errorf("%s is allow-listed with no explanatory comment — every entry needs its reason "+
				"and the condition for removing it", id)
		}
	}
}

func config(dbLastModified string) string {
	return `{
  "config": {
    "protocol_version": "v1.0.0",
    "scanner_name": "govulncheck",
    "scanner_version": "v1.6.0",
    "db": "https://vuln.go.dev",
    "db_last_modified": "` + dbLastModified + `",
    "go_version": "go1.26.11",
    "scan_level": "symbol",
    "scan_mode": "source"
  }
}`
}

func sbom() string {
	return `{
  "SBOM": {
    "go_version": "go1.26.11",
    "modules": [
      {"path": "github.com/suryakencana007/tamper"},
      {"path": "github.com/crewjam/saml", "version": "v0.6.3"}
    ]
  }
}`
}

// finding renders a finding message PRETTY-PRINTED, because that is the shape that broke the gate.
func finding(osv string, symbolLevel bool) string {
	trace := `[]`
	if symbolLevel {
		trace = `[
      {
        "module": "github.com/suryakencana007/tamper",
        "version": "",
        "package": "github.com/suryakencana007/tamper/saml",
        "function": "Provider.ParseAssertion",
        "filename": "saml/parse.go",
        "line": 64
      }
    ]`
	}
	return `{
  "finding": {
    "osv": "` + osv + `",
    "fixed_version": "",
    "trace": ` + trace + `
  }
}`
}

// findingInDependency renders a finding whose trace stops inside a dependency: present, traced, and
// not reachable from this module.
func findingInDependency(osv string) string {
	return `{
  "finding": {
    "osv": "` + osv + `",
    "fixed_version": "",
    "trace": [
      {
        "module": "github.com/crewjam/saml",
        "version": "v0.6.3",
        "package": "github.com/crewjam/saml",
        "function": "ServiceProvider.ParseResponse"
      }
    ]
  }
}`
}

func stream(objs ...string) string { return strings.Join(objs, "\n") + "\n" }

func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}
