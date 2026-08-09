package tenant

// ID identifies the tenant an operation belongs to.
//
// # The zero value is invalid, on purpose
//
// Phase 7's §5 M6 requires that `""` stay a legal tenant — "an explicit
// single-tenant value, not an unset one". A bare string cannot express that.
// `""` would be simultaneously the single-tenant value and what a caller who
// forgot to thread the tenant through passes, and nothing downstream could
// tell the two apart.
//
// That ambiguity has already been ruled on twice in this phase. The leak
// suite REMOVED its `""` mode because "nothing the suite can observe
// separates a single-tenant store from a leaky pooled one", and §6.2 settles
// ties the same way every time: ambiguous means deny. Threading a string
// would reintroduce the ambiguity at the API surface one release after the
// harness rejected it.
//
// So ID carries whether it was set at all. A caller who forgets passes the
// zero value, which is invalid and denies. A deployment that genuinely has
// one tenant writes [Single] and says so out loud.
//
// ID is comparable, so it works as a map key — which the per-tenant registry
// caches rely on.
type ID struct {
	v   string
	set bool
}

// Single is the explicit single-tenant value: `""`, said deliberately.
//
// This is what a single-tenant deployment passes. It is legal everywhere a
// tenant is required, and it is NOT what a caller who forgot produces — that
// is the zero ID, which denies.
var Single = ID{set: true}

// New returns the ID for an application-defined tenant identifier.
//
// New("") is INVALID and returns the zero ID. It is deliberately not an alias
// for [Single]: an empty string arriving out of a `tid` claim, a routing
// header or a config lookup means the lookup produced nothing, and that is
// precisely the case that must deny rather than quietly select the
// single-tenant bucket. A deployment that means `""` writes [Single].
//
// The identifier is opaque and is never parsed by tamper.
func New(s string) ID {
	if s == "" {
		return ID{}
	}
	return ID{v: s, set: true}
}

// Valid reports whether the ID was set explicitly. The zero value is not.
//
// Every tenant-scoped entry point checks this and denies when it is false.
func (i ID) Valid() bool { return i.set }

// IsSingle reports whether the ID is the explicit single-tenant value.
//
// False for the zero ID: unset is not single-tenant, it is unset.
func (i ID) IsSingle() bool { return i.set && i.v == "" }

// String returns the underlying identifier, or "" for [Single].
//
// It also returns "" for the zero ID, so String alone cannot be used to
// decide whether a tenant was supplied — call [Valid] for that. This is the
// one place the old ambiguity still exists, and it is confined to a display
// and storage helper rather than sitting in every signature.
func (i ID) String() string { return i.v }
