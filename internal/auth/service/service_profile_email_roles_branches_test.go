package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
)

type profileEmailRepoStub struct {
	fakeRepo

	createEmailTokenErr error

	verifyTokenOut domain.EmailVerificationToken
	verifyTokenErr error

	consumeVerifyErr error
	setVerifiedErr   error

	userOut domain.User
	userErr error

	updateNamesErr error
	updatedUID     uuid.UUID
	updatedFirst   string
	updatedLast    string

	getRoleByNameOut domain.Role
	getRoleByNameErr error

	createRoleOut domain.Role
	createRoleErr error
	createRoleCnt int
	createdNames  []string
}

func (r *profileEmailRepoStub) CreateEmailVerificationToken(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, string, time.Time) error {
	return r.createEmailTokenErr
}

func (r *profileEmailRepoStub) GetEmailVerificationTokenByHash(context.Context, string) (domain.EmailVerificationToken, error) {
	if r.verifyTokenErr != nil {
		return domain.EmailVerificationToken{}, r.verifyTokenErr
	}
	return r.verifyTokenOut, nil
}

func (r *profileEmailRepoStub) ConsumeEmailVerificationToken(context.Context, string) error { return r.consumeVerifyErr }
func (r *profileEmailRepoStub) SetUserEmailVerified(context.Context, uuid.UUID, bool) error {
	return r.setVerifiedErr
}

func (r *profileEmailRepoStub) GetUserByID(context.Context, uuid.UUID) (domain.User, error) {
	if r.userErr != nil {
		return domain.User{}, r.userErr
	}
	return r.userOut, nil
}

func (r *profileEmailRepoStub) UpdateUserNames(ctx context.Context, userID uuid.UUID, firstName, lastName string) error {
	r.updatedUID = userID
	r.updatedFirst = firstName
	r.updatedLast = lastName
	return r.updateNamesErr
}

func (r *profileEmailRepoStub) GetRoleByName(ctx context.Context, tenantID uuid.UUID, name string) (domain.Role, error) {
	if r.getRoleByNameErr != nil {
		return domain.Role{}, r.getRoleByNameErr
	}
	return r.getRoleByNameOut, nil
}

func (r *profileEmailRepoStub) CreateRole(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, description string) (domain.Role, error) {
	r.createRoleCnt++
	r.createdNames = append(r.createdNames, name)
	if r.createRoleErr != nil {
		return domain.Role{}, r.createRoleErr
	}
	if r.createRoleOut.ID == uuid.Nil {
		r.createRoleOut = domain.Role{ID: id, TenantID: tenantID, Name: name, Description: description}
	}
	return r.createRoleOut, nil
}

func TestService_EmailVerification_Profile_Roles_Branches(t *testing.T) {
	repo := &profileEmailRepoStub{}
	s := &Service{
		repo:     repo,
		settings: magicSettingsStub{},
		pub: publisherFunc(func(context.Context, evdomain.Event) error {
			return nil
		}),
	}

	tenantID := uuid.New()
	userID := uuid.New()

	repo.createEmailTokenErr = errors.New("create failed")
	if err := s.SendEmailVerification(context.Background(), userID, tenantID, "u@example.com"); err == nil {
		t.Fatal("expected CreateEmailVerificationToken error")
	}
	repo.createEmailTokenErr = nil
	if err := s.SendEmailVerification(context.Background(), userID, tenantID, "u@example.com"); err != nil {
		t.Fatalf("SendEmailVerification unexpected err=%v", err)
	}

	if err := s.VerifyEmail(context.Background(), ""); err == nil || err.Error() != "token required" {
		t.Fatalf("expected token required, got %v", err)
	}

	repo.verifyTokenErr = errors.New("missing")
	if err := s.VerifyEmail(context.Background(), "tok"); err == nil || err.Error() != "invalid or expired token" {
		t.Fatalf("expected invalid token error, got %v", err)
	}
	repo.verifyTokenErr = nil

	consumed := time.Now().Add(-time.Minute)
	repo.verifyTokenOut = domain.EmailVerificationToken{UserID: userID, TenantID: tenantID, Email: "u@example.com", ExpiresAt: time.Now().Add(time.Hour), ConsumedAt: &consumed}
	if err := s.VerifyEmail(context.Background(), "tok"); err == nil || err.Error() != "token expired or already used" {
		t.Fatalf("expected consumed/expired error, got %v", err)
	}

	repo.verifyTokenOut = domain.EmailVerificationToken{UserID: userID, TenantID: tenantID, Email: "u@example.com", ExpiresAt: time.Now().Add(time.Hour)}
	repo.consumeVerifyErr = errors.New("consume failed")
	if err := s.VerifyEmail(context.Background(), "tok"); err == nil {
		t.Fatal("expected consume verification token error")
	}
	repo.consumeVerifyErr = nil
	repo.setVerifiedErr = errors.New("set verified failed")
	if err := s.VerifyEmail(context.Background(), "tok"); err == nil {
		t.Fatal("expected set verified error")
	}
	repo.setVerifiedErr = nil
	if err := s.VerifyEmail(context.Background(), "tok"); err != nil {
		t.Fatalf("VerifyEmail unexpected err=%v", err)
	}

	repo.userErr = errors.New("user lookup failed")
	if err := s.UpdateProfile(context.Background(), userID, "", ""); err == nil {
		t.Fatal("expected UpdateProfile user lookup error")
	}
	repo.userErr = nil

	repo.userOut = domain.User{FirstName: "LegacyF", LastName: "LegacyL"}
	if err := s.UpdateProfile(context.Background(), userID, "", ""); err != nil {
		t.Fatalf("UpdateProfile fallback unexpected err=%v", err)
	}
	if repo.updatedFirst != "LegacyF" || repo.updatedLast != "LegacyL" {
		t.Fatalf("expected profile fallback names, got first=%q last=%q", repo.updatedFirst, repo.updatedLast)
	}
	if err := s.UpdateProfile(context.Background(), userID, "  New  ", "  Name "); err != nil {
		t.Fatalf("UpdateProfile trim unexpected err=%v", err)
	}
	if repo.updatedFirst != "New" || repo.updatedLast != "Name" {
		t.Fatalf("expected trimmed names, got first=%q last=%q", repo.updatedFirst, repo.updatedLast)
	}

	repo.getRoleByNameOut = domain.Role{ID: uuid.New(), TenantID: tenantID, Name: "admin"}
	role, err := s.GetOrCreateAdminRole(context.Background(), tenantID)
	if err != nil || role.Name != "admin" {
		t.Fatalf("GetOrCreateAdminRole existing unexpected role=%+v err=%v", role, err)
	}

	repo.getRoleByNameErr = errors.New("not found")
	repo.getRoleByNameOut = domain.Role{}
	role, err = s.GetOrCreateAdminRole(context.Background(), tenantID)
	if err != nil || role.Name != "admin" {
		t.Fatalf("GetOrCreateAdminRole create unexpected role=%+v err=%v", role, err)
	}

	repo.createRoleCnt = 0
	repo.createdNames = nil
	repo.getRoleByNameErr = nil
	repo.getRoleByNameOut = domain.Role{ID: uuid.New(), TenantID: tenantID, Name: "admin"}
	if err := s.SeedDefaultRoles(context.Background(), tenantID); err != nil {
		t.Fatalf("SeedDefaultRoles unexpected err=%v", err)
	}
	if repo.createRoleCnt != 0 {
		t.Fatalf("expected no role creation when admin/member already found, createRoleCnt=%d", repo.createRoleCnt)
	}

	repo.getRoleByNameErr = errors.New("missing")
	repo.createRoleErr = errors.New("create role failed")
	if err := s.SeedDefaultRoles(context.Background(), tenantID); err == nil {
		t.Fatal("expected SeedDefaultRoles create error")
	}
}
