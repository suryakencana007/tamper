package tenant

import "testing"

func TestEntitlements_UnionWidensCapabilities(t *testing.T) {
	group := Entitlements{SSOEnabled: true}
	org := Entitlements{SCIMEnabled: true}

	got := org.Union(group)
	if !got.SSOEnabled || !got.SCIMEnabled {
		t.Fatalf("Union = %+v, want both capabilities (a parent must not take away what the child bought)", got)
	}
}

// The cap rules, which are the whole reason Union is not a field-by-field max.
func TestEntitlements_UnionCap(t *testing.T) {
	cases := []struct {
		name  string
		e     Entitlements
		other Entitlements
		want  int
	}{
		{"unlimited beats finite", Entitlements{SSOEnabled: true}, Entitlements{MaxIdPConnections: 40}, 0},
		{"finite beats smaller finite", Entitlements{MaxIdPConnections: 40}, Entitlements{MaxIdPConnections: 10}, 40},
		{"larger wins either side", Entitlements{MaxIdPConnections: 10}, Entitlements{MaxIdPConnections: 40}, 40},
		// A record that state nothing states no cap: the zero cannot be read as
		// "unlimited" without handing every child of a capped group an uncapped
		// plan.
		{"a zero record states no cap", Entitlements{}, Entitlements{SSOEnabled: true, MaxIdPConnections: 3}, 3},
		{"and in the other direction", Entitlements{SSOEnabled: true, MaxIdPConnections: 3}, Entitlements{}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.e.Union(tc.other); got.MaxIdPConnections != tc.want {
				t.Fatalf("cap = %d, want %d", got.MaxIdPConnections, tc.want)
			}
			if got := tc.other.Union(tc.e); got.MaxIdPConnections != tc.want {
				t.Fatalf("commuted cap = %d, want %d (Union must be commutative)", got.MaxIdPConnections, tc.want)
			}
		})
	}
}

func TestEntitlements_UnionWithAZeroRecordIsTheZeroRecord(t *testing.T) {
	var zero Entitlements
	if got := zero.Union(zero); got != zero {
		t.Fatalf("Union(zero, zero) = %+v, want the zero record", got)
	}
}

func TestEntitlements_UnionIsIdempotent(t *testing.T) {
	e := Entitlements{SSOEnabled: true, MaxIdPConnections: 7}
	if got := e.Union(e); got != e {
		t.Fatalf("Union(e, e) = %+v, want e", got)
	}
}

// Union only ever widens. A property over the interesting shapes, because the
// individual cases above cannot cover "never narrows".
func TestEntitlements_UnionNeverNarrows(t *testing.T) {
	shapes := []Entitlements{
		{},
		{SSOEnabled: true},
		{SCIMEnabled: true},
		{MaxIdPConnections: 1},
		{MaxIdPConnections: 40},
		{SSOEnabled: true, SCIMEnabled: true, MaxIdPConnections: 0},
		{SSOEnabled: true, SCIMEnabled: true, MaxIdPConnections: 40},
	}
	for _, a := range shapes {
		for _, b := range shapes {
			got := a.Union(b)
			if a.SSOEnabled && !got.SSOEnabled || a.SCIMEnabled && !got.SCIMEnabled {
				t.Fatalf("Union(%+v, %+v) = %+v lost a capability", a, b, got)
			}
			// A finite cap that survives must not have shrunk. (0 is unlimited,
			// which is wider, not narrower.)
			if got.MaxIdPConnections > 0 && a.MaxIdPConnections > 0 && got.MaxIdPConnections < a.MaxIdPConnections {
				t.Fatalf("Union(%+v, %+v) = %+v narrowed the cap", a, b, got)
			}
		}
	}
}

func TestEntitlements_IsZero(t *testing.T) {
	zero := []Entitlements{{}, {SSOEnabled: false, SCIMEnabled: false, MaxIdPConnections: 0}}
	for _, e := range zero {
		if !e.IsZero() {
			t.Fatalf("IsZero(%+v) = false, want true", e)
		}
	}
	notZero := []Entitlements{
		{SSOEnabled: true},
		{SCIMEnabled: true},
		{MaxIdPConnections: 1},
		{MaxIdPConnections: 3, SSOEnabled: true},
	}
	for _, e := range notZero {
		if e.IsZero() {
			t.Fatalf("IsZero(%+v) = true, want false — a record that bought something keeps 0 as UNLIMITED", e)
		}
	}
}
