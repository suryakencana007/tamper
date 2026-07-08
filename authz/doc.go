// Package authz will define Tamper's Authorizer PDP — Check / CheckBulk /
// ListResources / ListSubjects — plus pluggable backends (SQL-RBAC default,
// Cedar/Casbin, OpenFGA/SpiceDB). The interface is the framework's spine;
// call sites depend on it, never on a concrete engine.
//
// Empty skeleton — Phase 1 of the extraction roadmap; the interface sketch
// and backend spectrum live in ../TAMPER-DESIGN.md.
package authz
