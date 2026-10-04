package espresso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/identity"
)

// totpIdentity scripts the three port calls the TOTP verify route makes.
type totpIdentity struct {
	IdentityService
	pendingErr error
	mintErr    error
	verified   int // how many times a code was checked
}

func (f *totpIdentity) VerifyTOTPPending(string) (string, error) { return "u-1", f.pendingErr }
func (f *totpIdentity) VerifyTOTP(context.Context, string, string) error {
	f.verified++
	return nil
}
func (f *totpIdentity) VerifyRecoveryCode(context.Context, string, string) error {
	f.verified++
	return nil
}
func (f *totpIdentity) IssueTokensForUser(context.Context, string) (AuthResult, error) {
	if f.mintErr != nil {
		return AuthResult{}, f.mintErr
	}
	return AuthResult{User: &identity.User{ID: "u-1", Email: "a@example.com"}}, nil
}

// wire renders a route error the way the framework writes it.
func wire(t *testing.T, err error) (int, string) {
	t.Helper()
	var w interface {
		WriteResponse(http.ResponseWriter) error
	}
	if !errors.As(err, &w) {
		t.Fatalf("error %v (%T) does not render a response", err, err)
	}
	rec := httptest.NewRecorder()
	if werr := w.WriteResponse(rec); werr != nil {
		t.Fatalf("WriteResponse: %v", werr)
	}
	return rec.Code, rec.Body.String()
}

func verifyTOTP(t *testing.T, svc *totpIdentity) error {
	t.Helper()
	_, err := testRoutes(t, svc).VerifyTOTP(context.Background(),
		&espressofw.JSON[TOTPVerifyReq]{Data: TOTPVerifyReq{SessionToken: "tok", Code: "123456"}})
	return err
}

// TD-18: the mint that ends the second leg refuses with ErrNotFound when
// the user is gone, and with the SAME error when the user is stored in
// another tenant. That refusal is not a server fault. It must look
// exactly like a pending token that is no longer good.
func TestAuthRoutes_TOTPVerify_MintNotFoundLooksLikeADeadSession(t *testing.T) {
	deadCode, deadBody := wire(t, verifyTOTP(t, &totpIdentity{pendingErr: errors.New("expired")}))
	if deadCode != http.StatusUnauthorized {
		t.Fatalf("fixture: a dead pending token should be a 401, got %d", deadCode)
	}

	// The shape identity.Core returns: the sentinel, wrapped.
	refused := &totpIdentity{mintErr: fmt.Errorf("%w: user u-1", identity.ErrNotFound)}
	code, body := wire(t, verifyTOTP(t, refused))
	if code != deadCode || body != deadBody {
		t.Fatalf("a refused mint answered %d %s; a dead pending token answers %d %s — the "+
			"difference tells the caller the code was right and the user is elsewhere",
			code, body, deadCode, deadBody)
	}
	if refused.verified != 1 {
		t.Fatalf("fixture: the code check should have run once, ran %d times", refused.verified)
	}
}

// The other mint failures keep the answers they had.
func TestAuthRoutes_TOTPVerify_OtherMintErrorsAreUnchanged(t *testing.T) {
	code, _ := wire(t, verifyTOTP(t, &totpIdentity{mintErr: errors.New("database is down")}))
	if code != http.StatusInternalServerError {
		t.Errorf("an unexpected mint failure answered %d, want 500", code)
	}

	code, body := wire(t, verifyTOTP(t, &totpIdentity{mintErr: identity.ErrUserInactive}))
	if code != http.StatusUnauthorized || !strings.Contains(body, "USER_INACTIVE") {
		t.Errorf("an inactive user answered %d %s, want 401 USER_INACTIVE", code, body)
	}
}
