package audit_test

import (
	"testing"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/tenant"
)

// A platform credential's audit actor is built with the ZERO tenant id, not tenant.Single, and
// espresso's comment says the choice is semantic: the stored bits are identical, so no test can
// tell the two apart. That claim is what this test pins.
//
// It is not decoration. If tenant.Single ever gains a marker — a set flag that reaches Actor's
// stored form — then the two DO become distinguishable, the "unobservable by construction" label
// on that choice becomes false, and somebody has to decide which one a platform credential
// should carry. Better that this fails with that sentence than that the decision quietly becomes
// observable and wrong.
func TestActorService_ZeroAndSingleTenantAreIndistinguishable(t *testing.T) {
	zero := audit.ActorService("sa", "provisioner", tenant.ID{})
	single := audit.ActorService("sa", "provisioner", tenant.Single)

	if zero != single {
		t.Fatalf("the two actor tenants are now DISTINGUISHABLE:\n zero   = %+v\n single = %+v\n"+
			"espresso/scimroutes.go and espresso/sagate.go choose the zero id deliberately, and "+
			"their comments claim no test can tell the difference; this is that test, so the "+
			"comments must be revisited", zero, single)
	}
	if zero.TenantID != "" {
		t.Errorf("actor.TenantID = %q, want empty — a platform credential has no home tenant, "+
			"and tenant.Single would be a claim about the deployment", zero.TenantID)
	}
}
