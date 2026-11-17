package crypto

// EnterMode distinguishes the two reasons a subject acts in a tenant other
// than their home: a member of that tenant, or a guest (a Console admin).
// It is carried on an entered token so a route can gate the two differently
// without a database lookup, and it lets the mint choose the right TTL:
// members live as long as an ordinary access token, guests use the shorter
// enter TTL.
type EnterMode string

const (
	// EnterModeMember is a direct membership of the target tenant.
	EnterModeMember EnterMode = "member"
	// EnterModeGuest is a guest binding (origin group:<id>).
	EnterModeGuest EnterMode = "guest"
)

// Valid reports whether m is a known enter mode.
func (m EnterMode) Valid() bool { return m == EnterModeMember || m == EnterModeGuest }
