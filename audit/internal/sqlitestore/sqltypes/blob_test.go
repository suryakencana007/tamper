package sqltypes_test

import (
	"bytes"
	"testing"

	"github.com/suryakencana007/tamper/audit/internal/sqlitestore/sqltypes"
)

// TestBlob_NilValuesAsEmptyNotNull is the property the type exists for: a nil
// Blob must never reach the driver as NULL, because the v4 columns are
// NOT NULL and their DEFAULT is unreachable through a generated INSERT.
func TestBlob_NilValuesAsEmptyNotNull(t *testing.T) {
	t.Parallel()

	v, err := sqltypes.Blob(nil).Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if v == nil {
		t.Fatal("nil Blob produced a NULL driver.Value; the NOT NULL columns reject it")
	}
	b, ok := v.([]byte)
	if !ok {
		t.Fatalf("want []byte, got %T", v)
	}
	if len(b) != 0 {
		t.Fatalf("want empty, got %x", b)
	}
}

func TestBlob_ValueRoundTripsContent(t *testing.T) {
	t.Parallel()

	want := []byte{0xde, 0xad, 0xbe, 0xef}
	v, err := sqltypes.Blob(want).Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if got := v.([]byte); !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestBlob_ScanNullReadsAsEmptyNotNil(t *testing.T) {
	t.Parallel()

	// Rows written before this type existed can hold a genuine NULL only if
	// the column allowed it; either way a NULL must not come back as a nil
	// slice, or a re-insert of the same value would fail where the read
	// succeeded.
	var b sqltypes.Blob
	if err := b.Scan(nil); err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if b == nil {
		t.Fatal("Scan(nil) left the Blob nil; want empty")
	}
	if len(b) != 0 {
		t.Fatalf("want empty, got %x", b)
	}
}

func TestBlob_ScanCopiesDriverBuffer(t *testing.T) {
	t.Parallel()

	// database/sql permits the driver to reuse its buffer after Scan
	// returns. Aliasing it would let a later row silently rewrite an
	// already-scanned hash commitment.
	src := []byte{1, 2, 3}
	var b sqltypes.Blob
	if err := b.Scan(src); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	src[0] = 0xff
	if b[0] != 1 {
		t.Fatalf("Blob aliased the driver buffer: got %x", b)
	}
}

func TestBlob_ScanRejectsUnsupported(t *testing.T) {
	t.Parallel()

	var b sqltypes.Blob
	if err := b.Scan(42); err == nil {
		t.Fatal("Scan(int) should fail rather than silently produce an empty Blob")
	}
}
