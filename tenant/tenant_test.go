package tenant

import (
	"errors"
	"testing"
)

// TestStatusConstantValues pins the persisted vocabulary. A Store maps
// its own status column onto these strings, so they are part of the
// storage contract — a later "tidy-up" rename is a silent data break on
// every deployed row, not a refactor.
func TestStatusConstantValues(t *testing.T) {
	for _, tc := range []struct {
		got  Status
		want string
	}{
		{StatusActive, "active"},
		{StatusSuspended, "suspended"},
		{StatusPending, "pending"},
	} {
		if string(tc.got) != tc.want {
			t.Errorf("status constant = %q, want %q", string(tc.got), tc.want)
		}
	}
}

// TestSentinelsAreDistinct guards the collapse that would make a
// suspended tenant satisfy an errors.Is(err, ErrNotFound) check, or the
// reverse. The two facts are deliberately different at the port and are
// only collapsed onto one another by a caller, at the wire (§6.3).
func TestSentinelsAreDistinct(t *testing.T) {
	if errors.Is(ErrSuspended, ErrNotFound) {
		t.Error("ErrSuspended matches ErrNotFound; the sentinels must stay distinct")
	}
	if errors.Is(ErrNotFound, ErrSuspended) {
		t.Error("ErrNotFound matches ErrSuspended; the sentinels must stay distinct")
	}
}

// TestDescriptorZeroValue pins that a zero Descriptor carries no
// implicit status. A caller must never read the zero value as "active".
func TestDescriptorZeroValue(t *testing.T) {
	var d Descriptor
	if d.Status != "" {
		t.Errorf("zero Descriptor.Status = %q, want empty", d.Status)
	}
	if d.Status == StatusActive {
		t.Error("zero Descriptor must not read as StatusActive")
	}
}
