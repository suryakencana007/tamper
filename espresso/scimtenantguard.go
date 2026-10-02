package espresso

import (
	"context"
	"errors"
	"net/http"

	scim "github.com/suryakencana007/tamper/scim"
)

// SCIM tenant guard (TD-15). The unscoped scim.UserStore / scim.GroupStore
// methods take no tenant, so a store shared by several tenants answers
// them from every tenant's rows. NewSCIMRoutes therefore never keeps the
// application's unscoped stores as it received them: it keeps them inside
// the guarding decorators below, which refuse a tenant-bound credential
// before delegating. The only way to hold the bare store is to declare
// SCIMConfig.TenantBoundStores.
//
// The guard lives in the store VALUE rather than at the call sites
// because a rule every caller must remember is a rule the next caller
// forgets. With the decorator in s.users / s.groups there is no unguarded
// store in the package to call by mistake.

// errSCIMNotTenantScoped is what a guarded store returns INSTEAD of
// calling the application's unscoped store for a tenant-bound credential.
// It never leaves the package: writeSCIMNotTenantScoped renders it,
// through the same write…StoreErr paths every other store error takes.
var errSCIMNotTenantScoped = errors.New(
	"tamper/espresso: tenant-bound credential on a SCIM surface built with neither " +
		"SCIMConfig.Tenancy nor SCIMConfig.TenantBoundStores")

// scimNotTenantScopedDetail is the §3.12 detail for that refusal. It names
// the two settings, because the reader is the operator looking at their
// IdP's provisioning log with nothing else to grep for, and it names no
// tenant and no resource: the answer is the same for every id, existing or
// not, so it cannot be used to probe another customer's directory. The
// CONFIG_ERROR prefix is the code espresso/decision.go answers a
// misconfigured gate with; the SCIM envelope has no code field, so it
// rides in the detail the way CIRCULAR_GROUP_REFERENCE does.
const scimNotTenantScopedDetail = "CONFIG_ERROR: this SCIM surface is not tenant-scoped " +
	"(neither SCIMConfig.Tenancy nor SCIMConfig.TenantBoundStores is set) " +
	"but the credential is bound to a tenant"

// requireUntenanted is the one predicate in front of every guarded store
// method.
//
// The unscoped methods take no tenant, so there is nothing to constrain
// them with. A principal that carries one is therefore a deployment
// misconfiguration — a pooled validator wired to a surface nobody declared
// tenant-safe — and the only two things to do with it are refuse, or serve
// it from every tenant's rows. This refuses, before the store is touched,
// on reads as much as writes.
//
// It cannot be a boot guard, which is where tenancy misconfiguration
// normally fails: NewSCIMRoutes never sees the validator, and what a
// validator returns is only known per token. So it fails on the first
// request instead, as a 500 rather than a 404 — nothing was looked up, and
// a 404 would report a deployment fault as a fact about the directory.
//
// An empty TenantID is the single-tenant deployment and passes untouched,
// which is what keeps that path byte-identical. So does a request with no
// principal at all: it is the caller's wiring that decides whether such a
// request can arrive here, exactly as before.
//
// The ok from GetPrincipal is deliberately ignored. It is false for a
// principal with an empty ID, and a credential that names a tenant but no
// account is still tenant-bound; reading ok would let it through.
func requireUntenanted(ctx context.Context) error {
	if p, _ := GetPrincipal(ctx); p.TenantID != "" {
		return errSCIMNotTenantScoped
	}
	return nil
}

// writeSCIMNotTenantScoped renders errSCIMNotTenantScoped. One writer, so
// the Users, Groups and List error paths answer with the same bytes.
func writeSCIMNotTenantScoped(w http.ResponseWriter) {
	WriteSCIMErrorTyped(w, http.StatusInternalServerError, scimNotTenantScopedDetail, "")
}

// guardedUserStore is the scim.UserStore NewSCIMRoutes keeps in place of
// the application's own: every method checks requireUntenanted, then
// delegates unchanged.
//
// next is a NAMED field, not an embedded interface, and every method is
// written out. Embedding would promote the port's methods, so a method
// added to scim.UserStore later would be served unguarded without a line
// of this file changing. Spelled out, the same addition fails to compile
// here until someone decides what the guard does with it.
//
// It implements scim.UserStore and deliberately nothing more. It must not
// be what the TenantScoped* assertion in NewSCIMRoutes sees — that runs on
// the application's store, before this wraps it.
type guardedUserStore struct{ next scim.UserStore }

var _ scim.UserStore = guardedUserStore{}

func (g guardedUserStore) Create(ctx context.Context, w scim.UserWrite, meta scim.WriteMeta) (scim.UserRecord, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.UserRecord{}, err
	}
	return g.next.Create(ctx, w, meta)
}

func (g guardedUserStore) Get(ctx context.Context, id string) (scim.UserRecord, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.UserRecord{}, err
	}
	return g.next.Get(ctx, id)
}

func (g guardedUserStore) Replace(ctx context.Context, id string, w scim.UserWrite, meta scim.WriteMeta) (scim.UserRecord, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.UserRecord{}, err
	}
	return g.next.Replace(ctx, id, w, meta)
}

func (g guardedUserStore) Delete(ctx context.Context, id string, meta scim.WriteMeta) error {
	if err := requireUntenanted(ctx); err != nil {
		return err
	}
	return g.next.Delete(ctx, id, meta)
}

func (g guardedUserStore) SavePatch(ctx context.Context, id string, w scim.UserWrite, ops []scim.Operation) (scim.UserRecord, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.UserRecord{}, err
	}
	return g.next.SavePatch(ctx, id, w, ops)
}

// List has no transport caller today (both List handlers go through
// ListFiltered). It is guarded anyway: the decorator is the port, and a
// port with one open method is an open port.
func (g guardedUserStore) List(ctx context.Context, startIndex, count int) (scim.UserPage, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.UserPage{}, err
	}
	return g.next.List(ctx, startIndex, count)
}

func (g guardedUserStore) ListFiltered(ctx context.Context, startIndex, count int, filter string) (scim.UserPage, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.UserPage{}, err
	}
	return g.next.ListFiltered(ctx, startIndex, count, filter)
}

// guardedGroupStore is guardedUserStore for scim.GroupStore; the same
// reasoning, method for method.
type guardedGroupStore struct{ next scim.GroupStore }

var _ scim.GroupStore = guardedGroupStore{}

func (g guardedGroupStore) Create(ctx context.Context, w scim.GroupWrite, meta scim.GroupWriteMeta) (scim.GroupRecord, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.GroupRecord{}, err
	}
	return g.next.Create(ctx, w, meta)
}

func (g guardedGroupStore) Get(ctx context.Context, id string) (scim.GroupRecord, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.GroupRecord{}, err
	}
	return g.next.Get(ctx, id)
}

func (g guardedGroupStore) Replace(ctx context.Context, id string, w scim.GroupWrite, meta scim.GroupWriteMeta) (scim.GroupRecord, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.GroupRecord{}, err
	}
	return g.next.Replace(ctx, id, w, meta)
}

func (g guardedGroupStore) Delete(ctx context.Context, id string, meta scim.GroupWriteMeta) error {
	if err := requireUntenanted(ctx); err != nil {
		return err
	}
	return g.next.Delete(ctx, id, meta)
}

func (g guardedGroupStore) SavePatch(ctx context.Context, id string, w scim.GroupWrite, ops []scim.Operation) (scim.GroupRecord, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.GroupRecord{}, err
	}
	return g.next.SavePatch(ctx, id, w, ops)
}

// ValidateMembers is the one most worth guarding. It returns only an
// error, so an open one "succeeds", and the write that follows nests
// another tenant's user into this tenant's group.
func (g guardedGroupStore) ValidateMembers(ctx context.Context, members []scim.MemberRef) error {
	if err := requireUntenanted(ctx); err != nil {
		return err
	}
	return g.next.ValidateMembers(ctx, members)
}

// List: see guardedUserStore.List.
func (g guardedGroupStore) List(ctx context.Context, startIndex, count int) (scim.GroupPage, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.GroupPage{}, err
	}
	return g.next.List(ctx, startIndex, count)
}

func (g guardedGroupStore) ListFiltered(ctx context.Context, startIndex, count int, filter string) (scim.GroupPage, error) {
	if err := requireUntenanted(ctx); err != nil {
		return scim.GroupPage{}, err
	}
	return g.next.ListFiltered(ctx, startIndex, count, filter)
}
