package tamper

// BootstrapAuditV4 exposes New's v4-anchor boot step to the external test
// package. New only ever hands it a *audit.SQLiteLogger, which can always
// bootstrap, so the "this logger cannot" guard is unreachable through New —
// and a guard no test can reach is one nobody notices being turned into a
// silent skip.
var BootstrapAuditV4 = bootstrapAuditV4
