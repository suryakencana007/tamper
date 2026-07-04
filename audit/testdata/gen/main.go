// Command gen regenerates internal/audit/testdata/v1.0-chain.json after
// a change to the canonical-payload v2 encoder. The fixture's stored
// PrevHash + Hash columns must round-trip through
// canonicalPayloadLegacyV2 + sha256; if the encoder changes (as it did
// in v1.4 — TD-AUDIT-09 — switching the timestamp from RFC3339Nano to
// UnixNano), every row's hash needs recomputing.
//
// Usage:
//
//	go run ./internal/audit/testdata/gen
//
// Reads the existing fixture, preserves every field except `prev_hash`
// and `hash`, recomputes the chain row-by-row under the current
// canonical_legacy_v2 encoder, and writes the regenerated JSON back to
// `internal/audit/testdata/v1.0-chain.json` with the same indentation
// shape as the committed file.
//
// This tool is committed alongside the fixture so future encoder
// changes have a documented regen path. Run it manually; CI doesn't
// invoke it.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// chainRow mirrors the on-disk row shape in v1.0-chain.json. Kept
// duplicate from internal/audit's own loader so this tool can be run
// without depending on the audit package (avoids a circular-build
// scenario where a broken audit package blocks the regen tool).
type chainRow struct {
	ID         string `json:"id"`
	OccurredAt string `json:"occurred_at"`
	Actor      struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"actor"`
	Action           string `json:"action"`
	TargetType       string `json:"target_type"`
	TargetID         string `json:"target_id"`
	ClusterID        string `json:"cluster_id"`
	DataJSON         string `json:"data_json"`
	PrevHash         string `json:"prev_hash"`
	Hash             string `json:"hash"`
	CanonicalVersion int    `json:"canonical_version"`
}

// canonicalPayloadLegacyV2 reproduces the v1.4+
// internal/audit/canonical_legacy_v2.go encoder. Inlined here so the
// regen tool stays self-contained; changes to the production encoder
// must be mirrored here AND in the production code path.
func canonicalPayloadLegacyV2(row chainRow, atUnixNanos int64, prevHash []byte) []byte {
	actorType := row.Actor.Type
	if actorType == "" {
		actorType = "user"
	}
	fields := []string{
		hex.EncodeToString(prevHash),
		strconv.FormatInt(atUnixNanos, 10),
		actorType,
		row.Actor.Name,
		row.Action,
		row.TargetType,
		row.TargetID,
		row.ClusterID,
		row.DataJSON,
	}
	return []byte(strings.Join(fields, "|"))
}

func main() {
	// Find the fixture file relative to the tool's CWD. `go run
	// ./internal/audit/testdata/gen` is invoked from the repo root.
	fixturePath := filepath.Join("internal", "audit", "testdata", "v1.0-chain.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		// Allow the tool to be run from inside the testdata/gen dir too.
		fixturePath = filepath.Join("..", "v1.0-chain.json")
		raw, err = os.ReadFile(fixturePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read fixture: %v\n", err)
			os.Exit(1)
		}
	}

	var rows []chainRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal: %v\n", err)
		os.Exit(1)
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "fixture is empty; nothing to regenerate")
		os.Exit(1)
	}

	prev := make([]byte, sha256.Size) // genesis
	for i := range rows {
		r := &rows[i]
		at, perr := time.Parse(time.RFC3339Nano, r.OccurredAt)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "row %d (id=%s): parse occurred_at %q: %v\n", i, r.ID, r.OccurredAt, perr)
			os.Exit(1)
		}
		payload := canonicalPayloadLegacyV2(*r, at.UnixNano(), prev)
		h := sha256.New()
		h.Write(prev)
		h.Write(payload)
		next := h.Sum(nil)

		r.PrevHash = hex.EncodeToString(prev)
		r.Hash = hex.EncodeToString(next)
		prev = next
	}

	out, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	out = append(out, '\n')
	if err := os.WriteFile(fixturePath, out, 0o644); err != nil { //nolint:gosec // fixture file, not a secret
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("regenerated %d rows in %s\n", len(rows), fixturePath)
}
