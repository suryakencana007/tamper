package tenanttest

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

// A leak suite that cannot fail guards nothing. These tests drive the
// suites with a recorder in place of *testing.T and assert that stores
// which leak on purpose FAIL them, and that the reference stores pass.

type fatalPanic struct{}

type recorderT struct {
	failed   bool
	messages []string
}

func (r *recorderT) Helper() {}

func (r *recorderT) Errorf(format string, args ...any) {
	r.failed = true
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
}

func (r *recorderT) Fatalf(format string, args ...any) {
	r.failed = true
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
	panic(fatalPanic{})
}

func (r *recorderT) Run(name string, f func(harnessT)) bool {
	sub := &recorderT{}
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				if _, ok := rec.(fatalPanic); !ok {
					panic(rec) // a real bug in the suite, not a recorded failure
				}
			}
		}()
		f(sub)
	}()
	if sub.failed {
		r.failed = true
		for _, m := range sub.messages {
			r.messages = append(r.messages, name+": "+m)
		}
	}
	return !sub.failed
}

func (r *recorderT) report() string { return strings.Join(r.messages, "\n  ") }

// failedCases returns the names of the suite cases that recorded a
// failure.
func (r *recorderT) failedCases() map[string]bool {
	out := map[string]bool{}
	for _, m := range r.messages {
		if i := strings.Index(m, ": "); i > 0 {
			out[m[:i]] = true
		}
	}
	return out
}

// leakMode is the bug a fixture has.
type leakMode int

const (
	// ignoresScope: the store forgot the tenant column in its WHERE.
	ignoresScope leakMode = iota
	// ignoresSubjectTenant: the store matches a subject on its bare
	// {Type, ID}, so two tenants' users with the same id are one.
	ignoresSubjectTenant
	// stampsTheAskedScope: the store forgot the tenant in its WHERE and
	// then stamps every row with the scope it was asked for, so the
	// rows look right. The engine's own filter cannot see this one.
	stampsTheAskedScope
)

func (m leakMode) String() string {
	return [...]string{"ignores the scope", "ignores the subject's tenant", "stamps the asked scope"}[m]
}

// --- a leaky BindingStore ----------------------------------------------

type leakyBindings struct {
	mode leakMode
	all  []authz.Binding
}

func (l *leakyBindings) grant(b authz.Binding) error { l.all = append(l.all, b); return nil }

func (l *leakyBindings) scopeOK(b authz.Binding, scope tenant.ID) bool {
	return l.mode != ignoresSubjectTenant || b.Tenant == scope
}

func (l *leakyBindings) subjectOK(b authz.Binding, sub authz.Subject) bool {
	if l.mode == ignoresSubjectTenant {
		return b.Subject.Type == sub.Type && b.Subject.ID == sub.ID
	}
	return b.Subject == sub
}

func (l *leakyBindings) out(b authz.Binding, scope tenant.ID) authz.Binding {
	if l.mode == stampsTheAskedScope {
		b.Tenant = scope
	}
	return b
}

func (l *leakyBindings) BindingsFor(_ context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error) {
	var got []authz.Binding
	for _, b := range l.all {
		if l.scopeOK(b, scope) && l.subjectOK(b, sub) && b.Resource == res {
			got = append(got, l.out(b, scope))
		}
	}
	return got, nil
}

func (l *leakyBindings) BindingsForSubject(_ context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error) {
	var got []authz.Binding
	for _, b := range l.all {
		if l.scopeOK(b, scope) && l.subjectOK(b, sub) && b.Resource.Type == resourceType && b.Resource.ID != "" {
			got = append(got, l.out(b, scope))
		}
	}
	return got, nil
}

func (l *leakyBindings) BindingsOnResource(_ context.Context, scope tenant.ID, res authz.Resource) ([]authz.Binding, error) {
	var got []authz.Binding
	for _, b := range l.all {
		if l.scopeOK(b, scope) && b.Resource == res {
			got = append(got, l.out(b, scope))
		}
	}
	return got, nil
}

func TestBindingSuite_PassesAgainstTheReferenceStore(t *testing.T) {
	RunBindingStoreLeakSuite(t, func() BindingHarness {
		s := authz.NewMemStore()
		return BindingHarness{Store: s, Grant: func(b authz.Binding) error { s.Grant(b); return nil }}
	})
}

func TestBindingSuite_FailsAgainstLeakyStores(t *testing.T) {
	for mode, wantCases := range map[leakMode][]string{
		ignoresScope:         {"BindingsFor", "BindingsForSubject", "BindingsOnResource"},
		stampsTheAskedScope:  {"BindingsFor", "BindingsForSubject", "BindingsOnResource"},
		ignoresSubjectTenant: {"BindingsFor", "BindingsForSubject"},
	} {
		t.Run(mode.String(), func(t *testing.T) {
			rec := &recorderT{}
			runBindingSuite(rec, func() BindingHarness {
				s := &leakyBindings{mode: mode}
				return BindingHarness{Store: s, Grant: s.grant}
			})
			if !rec.failed {
				t.Fatalf("the suite PASSED a BindingStore that %s", mode)
			}
			failed := rec.failedCases()
			for _, c := range wantCases {
				if !failed[c] {
					t.Errorf("case %s did not catch a store that %s.\nrecorded:\n  %s", c, mode, rec.report())
				}
			}
		})
	}
}

// --- a leaky PermissionStore -------------------------------------------

type permGrant struct {
	scope tenant.ID
	sub   authz.Subject
	res   authz.Resource
	key   string
}

type leakyPermissions struct {
	mode   leakMode
	grants []permGrant
	supers []permGrant // scope + sub only
}

func (l *leakyPermissions) grant(scope tenant.ID, sub authz.Subject, res authz.Resource, keys ...string) error {
	for _, k := range keys {
		l.grants = append(l.grants, permGrant{scope, sub, res, k})
	}
	return nil
}

func (l *leakyPermissions) grantSuperuser(scope tenant.ID, sub authz.Subject) error {
	l.supers = append(l.supers, permGrant{scope: scope, sub: sub})
	return nil
}

func (l *leakyPermissions) scopeOK(g permGrant, scope tenant.ID) bool {
	return l.mode == ignoresSubjectTenant && g.scope == scope || l.mode != ignoresSubjectTenant
}

func (l *leakyPermissions) subjectOK(g permGrant, sub authz.Subject) bool {
	if l.mode == ignoresSubjectTenant {
		return g.sub.Type == sub.Type && g.sub.ID == sub.ID
	}
	return g.sub == sub
}

func (l *leakyPermissions) isSuper(scope tenant.ID, sub authz.Subject) bool {
	for _, g := range l.supers {
		if l.scopeOK(g, scope) && l.subjectOK(g, sub) {
			return true
		}
	}
	return false
}

func (l *leakyPermissions) PermissionsFor(_ context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) (authz.PermissionSetResult, error) {
	if l.isSuper(scope, sub) {
		return authz.PermissionSetResult{Superuser: true}, nil
	}
	keys := map[string]struct{}{}
	for _, g := range l.grants {
		if l.scopeOK(g, scope) && l.subjectOK(g, sub) && g.res == res {
			keys[g.key] = struct{}{}
		}
	}
	return authz.PermissionSetResult{Keys: keys}, nil
}

func (l *leakyPermissions) ResourcesWithPermission(_ context.Context, scope tenant.ID, sub authz.Subject, key string, resourceType string) ([]authz.Resource, bool, error) {
	if l.isSuper(scope, sub) {
		return nil, true, nil
	}
	var out []authz.Resource
	for _, g := range l.grants {
		if l.scopeOK(g, scope) && l.subjectOK(g, sub) && g.key == key && g.res.Type == resourceType && g.res.ID != "" {
			out = append(out, g.res)
		}
	}
	return out, false, nil
}

func (l *leakyPermissions) SubjectsWithPermission(_ context.Context, scope tenant.ID, key string, res authz.Resource) ([]authz.Subject, error) {
	var out []authz.Subject
	for _, g := range l.grants {
		if l.scopeOK(g, scope) && g.key == key && g.res == res {
			out = append(out, g.sub)
		}
	}
	for _, g := range l.supers {
		if l.scopeOK(g, scope) {
			out = append(out, g.sub)
		}
	}
	return out, nil
}

func TestPermissionSuite_PassesAgainstTheReferenceStore(t *testing.T) {
	RunPermissionStoreLeakSuite(t, func() PermissionHarness {
		s := authz.NewMemPermissionStore()
		return PermissionHarness{
			Store: s,
			Grant: func(scope tenant.ID, sub authz.Subject, res authz.Resource, keys ...string) error {
				s.Grant(scope, sub, res, keys...)
				return nil
			},
			GrantSuperuser: func(scope tenant.ID, sub authz.Subject) error { s.GrantSuperuser(scope, sub); return nil },
		}
	})
}

func TestPermissionSuite_FailsAgainstLeakyStores(t *testing.T) {
	for mode, wantCases := range map[leakMode][]string{
		ignoresScope:         {"PermissionsFor", "ResourcesWithPermission", "SubjectsWithPermission", "Superuser"},
		ignoresSubjectTenant: {"PermissionsFor", "ResourcesWithPermission", "Superuser"},
	} {
		t.Run(mode.String(), func(t *testing.T) {
			rec := &recorderT{}
			runPermissionSuite(rec, func() PermissionHarness {
				s := &leakyPermissions{mode: mode}
				return PermissionHarness{Store: s, Grant: s.grant, GrantSuperuser: s.grantSuperuser}
			})
			if !rec.failed {
				t.Fatalf("the suite PASSED a PermissionStore that %s", mode)
			}
			failed := rec.failedCases()
			for _, c := range wantCases {
				if !failed[c] {
					t.Errorf("case %s did not catch a store that %s.\nrecorded:\n  %s", c, mode, rec.report())
				}
			}
		})
	}
}

// A store with no superusers leaves GrantSuperuser nil, and the suite
// still runs the other cases.
func TestPermissionSuite_RunsWithoutSuperuserSupport(t *testing.T) {
	rec := &recorderT{}
	runPermissionSuite(rec, func() PermissionHarness {
		s := authz.NewMemPermissionStore()
		return PermissionHarness{Store: s, Grant: func(scope tenant.ID, sub authz.Subject, res authz.Resource, keys ...string) error {
			s.Grant(scope, sub, res, keys...)
			return nil
		}}
	})
	if rec.failed {
		t.Fatalf("the suite failed a compliant store without superuser support:\n  %s", rec.report())
	}
}
