package audit

import "strings"

// ReservedActionPrefix namespaces the audit chain machinery's own actions.
// Every action the chain subsystem reads (ActionAuditChainRestart,
// ActionAuditChainMigrate) lives under it. Consumers own all other action
// vocabulary but MUST NOT mint actions in this namespace from untrusted
// input — see IsReservedAction.
const ReservedActionPrefix = "system.audit."

// IsReservedAction reports whether a is in the ReservedActionPrefix
// namespace the chain subsystem reserves for its own segment markers.
//
// SECURITY — the fence a consumer must place, because the framework cannot.
// A row whose action equals ActionAuditChainRestart becomes Verify()'s walk
// root (audit_sqlite.go verifyRows roots the walk at the most recent such
// row), so an attacker who can inject that exact action string gets Verify()
// to skip every event before their row — a silent truncation of the
// tamper-evidence guarantee. Tamper cannot block this at Logger.Log: the
// legitimate anchor rows are emitted through the very same Log path, and the
// attack string is one of the legitimate anchors, so no carve-out
// distinguishes them. The only place the distinction exists is the
// consumer's own boundary where untrusted input becomes an Action. A
// consumer that derives actions from any user-influenced value MUST reject
// IsReservedAction(a) there. A consumer with a fixed, code-defined action
// catalog (e.g. Barista) is already safe and needs no guard.
func IsReservedAction(a Action) bool {
	return strings.HasPrefix(string(a), ReservedActionPrefix)
}

// Chain-segment anchor actions. Unlike the caller-defined action /
// resource strings that ride through ordinary Event emissions, these two
// action values are load-bearing for the hash-chain machinery itself:
// the verify path (verify_boot.go / audit_sqlite.go) and the migration
// path (migration.go) recognise them as chain-segment boundaries.
//
// They were lifted out of Barista's Barista-specific event catalog
// (internal/audit/eventtypes.go, deliberately NOT lifted into Tamper) as
// the only two catalog constants the generic core depends on. Callers
// remain free to define their own action / resource vocabulary for every
// other Event; these two are reserved by the chain subsystem.
const (
	// ActionAuditChainRestart marks a hash-chain genesis row: PrevHash is
	// the HashSize zero-byte sentinel and the row opens a new canonical
	// payload segment. Verify() walks forward from the most-recent
	// chain-restart row, treating it as the segment anchor. A caller
	// emits one (via Logger.Log with Action=ActionAuditChainRestart and
	// an explicit CanonicalVersion) exactly once per chain segment —
	// typically at first boot after an encoder-version bump.
	ActionAuditChainRestart Action = "system.audit.chain_restart"

	// ActionAuditChainMigrate marks that an in-place chain rehash / encoder
	// migration ran against an existing segment (see
	// SQLiteLogger.MigrateLegacyV2Hashes / RehashChainInPlace). The row is
	// a logical segment boundary for the boot-time verify walk
	// (VerifyChainPostMigration) and its presence is the idempotency key
	// for HasChainMigrate so the migration doesn't re-run on every restart.
	ActionAuditChainMigrate Action = "system.audit.chain_migrate"
)
