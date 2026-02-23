package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/keys"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
)

type invitationOpsRepoStub struct {
	fakeRepo
	acceptID      uuid.UUID
	acceptErr     error
	invByHash     domain.Invitation
	invByHashErr  error
	identityByEM  domain.AuthIdentity
	identityErr   error
	roleByName    domain.Role
	roleErr       error
	addUserRoleN  int
	createInvN    int
	createdEmail  string
	createdTenant *uuid.UUID
	createdRole   string
	lookupEmail   string

	setEmailVerifiedN int
	userOut           domain.User
	userErr           error
}

func (r *invitationOpsRepoStub) CreateInvitation(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID, email, tokenHash, role string, invitedBy *uuid.UUID, expiresAt time.Time) (domain.Invitation, error) {
	r.createInvN++
	r.createdEmail = email
	r.createdTenant = tenantID
	r.createdRole = role
	return domain.Invitation{ID: id, TenantID: tenantID, Email: email, Role: role, Status: "pending", ExpiresAt: expiresAt}, nil
}

func (r *invitationOpsRepoStub) AcceptInvitation(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	if r.acceptErr != nil {
		return uuid.Nil, r.acceptErr
	}
	return r.acceptID, nil
}

func (r *invitationOpsRepoStub) GetInvitationByHash(ctx context.Context, tokenHash string) (domain.Invitation, error) {
	if r.invByHashErr != nil {
		return domain.Invitation{}, r.invByHashErr
	}
	return r.invByHash, nil
}

func (r *invitationOpsRepoStub) GetAuthIdentityByEmailTenant(ctx context.Context, tenantID uuid.UUID, email string) (domain.AuthIdentity, error) {
	r.lookupEmail = email
	if r.identityErr != nil {
		return domain.AuthIdentity{}, r.identityErr
	}
	return r.identityByEM, nil
}

func (r *invitationOpsRepoStub) SetUserEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error {
	r.setEmailVerifiedN++
	return nil
}

func (r *invitationOpsRepoStub) GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error) {
	if r.userErr != nil {
		return domain.User{}, r.userErr
	}
	if r.userOut.ID == uuid.Nil {
		return domain.User{ID: userID, IsActive: true}, nil
	}
	return r.userOut, nil
}

type txStub struct {
	rollbackN int
	commitN   int
	commitErr error
}

func (t *txStub) Rollback(context.Context) error {
	t.rollbackN++
	return nil
}

func (t *txStub) Commit(context.Context) error {
	t.commitN++
	return t.commitErr
}

type txInvitationRepoStub struct {
	*invitationOpsRepoStub
	tx       *txStub
	txRepo   domain.Repository
	beginErr error
}

func (r *txInvitationRepoStub) BeginTx(context.Context) (interface {
	Rollback(context.Context) error
	Commit(context.Context) error
}, domain.Repository, error) {
	if r.beginErr != nil {
		return nil, nil, r.beginErr
	}
	return r.tx, r.txRepo, nil
}

func (r *invitationOpsRepoStub) GetRoleByName(ctx context.Context, tenantID uuid.UUID, name string) (domain.Role, error) {
	if r.roleErr != nil {
		return domain.Role{}, r.roleErr
	}
	return r.roleByName, nil
}

func (r *invitationOpsRepoStub) AddUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error {
	r.addUserRoleN++
	return nil
}

func TestService_InviteUser_NormalizesEmailAndPublishesEvent(t *testing.T) {
	tenantID := uuid.New()
	invitedBy := uuid.New()
	repo := &invitationOpsRepoStub{}
	events := make([]evdomain.Event, 0, 1)
	s := &Service{
		repo:     repo,
		settings: fakeSettings{},
		pub: publisherFunc(func(ctx context.Context, e evdomain.Event) error {
			events = append(events, e)
			return nil
		}),
	}

	if _, _, err := s.InviteUser(context.Background(), domain.InviteUserInput{Email: "", InvitedBy: invitedBy, TenantID: &tenantID}); err == nil {
		t.Fatal("expected email required error")
	}

	inv, raw, err := s.InviteUser(context.Background(), domain.InviteUserInput{
		TenantID:  &tenantID,
		Email:     " USER@Example.com ",
		Role:      "admin",
		InvitedBy: invitedBy,
	})
	if err != nil {
		t.Fatalf("InviteUser error: %v", err)
	}
	if raw == "" || inv.ID == uuid.Nil {
		t.Fatalf("expected raw token and invitation id, got token=%q inv=%+v", raw, inv)
	}
	if repo.createInvN != 1 || repo.createdEmail != "user@example.com" {
		t.Fatalf("expected normalized email persisted once, got n=%d email=%q", repo.createInvN, repo.createdEmail)
	}
	if len(events) != 1 || events[0].Type != "auth.invitation.created" {
		t.Fatalf("expected invitation created event, got %#v", events)
	}
}

func TestRunAcceptInvitationOps_ErrorAndSuccessPaths(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	authID := uuid.New()
	inv := domain.Invitation{ID: uuid.New(), TenantID: &tenantID, Email: "u@example.com", Role: "admin", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
	in := domain.AcceptInvitationInput{Token: "tok", Password: "Password!123", FirstName: "U", LastName: "Ser"}

	s := &Service{}
	repo := &invitationOpsRepoStub{acceptID: uuid.Nil}
	err := s.runAcceptInvitationOps(context.Background(), repo, userID, authID, inv, in, []string{"admin"}, "hash", "tokenHash")
	if err == nil || err.Error() != "invitation could not be accepted (already used or expired)" {
		t.Fatalf("expected nil accepted-id error, got %v", err)
	}

	repo.acceptID = uuid.New()
	repo.roleErr = errors.New("missing role")
	err = s.runAcceptInvitationOps(context.Background(), repo, userID, authID, inv, in, []string{"admin"}, "hash", "tokenHash")
	if err == nil {
		t.Fatal("expected role lookup error")
	}

	repo.roleErr = nil
	repo.roleByName = domain.Role{ID: uuid.New(), Name: "admin"}
	err = s.runAcceptInvitationOps(context.Background(), repo, userID, authID, inv, in, []string{"admin"}, "hash", "tokenHash")
	if err != nil {
		t.Fatalf("expected successful runAcceptInvitationOps, got %v", err)
	}
	if repo.addUserRoleN == 0 {
		t.Fatal("expected AddUserRole call for invitation role assignment")
	}
}

func TestRunAdminCreateUserOps_RoleAssignmentErrors(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	authID := uuid.New()
	in := domain.AdminCreateUserInput{TenantID: tenantID, Email: "u@example.com", Password: "Password!123", Roles: []string{"admin"}}
	s := &Service{}
	repo := &invitationOpsRepoStub{roleErr: errors.New("role missing")}

	err := s.runAdminCreateUserOps(context.Background(), repo, userID, authID, in, []string{"admin"}, "hash")
	if err == nil {
		t.Fatal("expected role lookup error")
	}

	repo.roleErr = nil
	repo.roleByName = domain.Role{} // nil UUID branch
	err = s.runAdminCreateUserOps(context.Background(), repo, userID, authID, in, []string{"admin"}, "hash")
	if err == nil {
		t.Fatal("expected nil role id error")
	}
}

func TestService_AcceptInvitation_ValidationAndStateErrors(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	now := time.Now().UTC()

	t.Run("missing token or password", func(t *testing.T) {
		s := &Service{repo: &invitationOpsRepoStub{}, settings: fakeSettings{}}
		_, err := s.AcceptInvitation(ctx, domain.AcceptInvitationInput{Token: "", Password: ""})
		if err == nil || err.Error() != "token and password are required" {
			t.Fatalf("expected token/password required error, got %v", err)
		}
	})

	t.Run("invalid token lookup", func(t *testing.T) {
		s := &Service{repo: &invitationOpsRepoStub{invByHashErr: errors.New("not found")}, settings: fakeSettings{}}
		_, err := s.AcceptInvitation(ctx, domain.AcceptInvitationInput{Token: "bad", Password: "Password!123"})
		if err == nil || err.Error() != "invalid or expired invitation" {
			t.Fatalf("expected invalid-or-expired invitation error, got %v", err)
		}
	})

	t.Run("invitation not pending", func(t *testing.T) {
		repo := &invitationOpsRepoStub{invByHash: domain.Invitation{ID: uuid.New(), TenantID: &tenantID, Status: "revoked", ExpiresAt: now.Add(time.Hour)}}
		s := &Service{repo: repo, settings: fakeSettings{}}
		_, err := s.AcceptInvitation(ctx, domain.AcceptInvitationInput{Token: "tok", Password: "Password!123"})
		if err == nil || err.Error() != "invitation has already been used or revoked" {
			t.Fatalf("expected revoked/used invitation error, got %v", err)
		}
	})

	t.Run("invitation expired", func(t *testing.T) {
		repo := &invitationOpsRepoStub{invByHash: domain.Invitation{ID: uuid.New(), TenantID: &tenantID, Status: "pending", ExpiresAt: now.Add(-time.Minute)}}
		s := &Service{repo: repo, settings: fakeSettings{}}
		_, err := s.AcceptInvitation(ctx, domain.AcceptInvitationInput{Token: "tok", Password: "Password!123"})
		if err == nil || err.Error() != "invitation has expired" {
			t.Fatalf("expected invitation expired error, got %v", err)
		}
	})

	t.Run("invitation without tenant", func(t *testing.T) {
		repo := &invitationOpsRepoStub{invByHash: domain.Invitation{ID: uuid.New(), TenantID: nil, Status: "pending", ExpiresAt: now.Add(time.Hour)}}
		s := &Service{repo: repo, settings: fakeSettings{}}
		_, err := s.AcceptInvitation(ctx, domain.AcceptInvitationInput{Token: "tok", Password: "Password!123"})
		if err == nil || err.Error() != "invitation does not have a tenant" {
			t.Fatalf("expected tenant missing error, got %v", err)
		}
	})

	t.Run("password policy violation", func(t *testing.T) {
		repo := &invitationOpsRepoStub{invByHash: domain.Invitation{ID: uuid.New(), TenantID: &tenantID, Status: "pending", ExpiresAt: now.Add(time.Hour)}}
		s := &Service{repo: repo, settings: fakeSettings{}}
		_, err := s.AcceptInvitation(ctx, domain.AcceptInvitationInput{Token: "tok", Password: "short"})
		if err == nil || err.Error() == "" {
			t.Fatalf("expected password policy violation error, got %v", err)
		}
	})

	t.Run("successful acceptance issues tokens", func(t *testing.T) {
		repo := &invitationOpsRepoStub{
			invByHash: domain.Invitation{ID: uuid.New(), TenantID: &tenantID, Email: "u@example.com", Status: "pending", ExpiresAt: now.Add(time.Hour)},
			acceptID:  uuid.New(),
			userOut:   domain.User{ID: uuid.New(), IsActive: true, FirstName: "U", LastName: "Ser"},
		}
		s := &Service{
			repo:     repo,
			settings: fakeSettings{},
			pub:      publisherFunc(func(context.Context, evdomain.Event) error { return nil }),
		}
		km, err := keys.NewManager("ES256", "", "")
		if err != nil {
			t.Fatalf("new key manager: %v", err)
		}
		s.SetKeyManager(km)

		toks, err := s.AcceptInvitation(ctx, domain.AcceptInvitationInput{Token: "tok", Password: "Password!123", FirstName: "U", LastName: "Ser"})
		if err != nil {
			t.Fatalf("AcceptInvitation unexpected err=%v", err)
		}
		if toks.AccessToken == "" || toks.RefreshToken == "" {
			t.Fatalf("expected issued tokens, got %+v", toks)
		}
	})
}

func TestService_AdminCreateUser_ValidationAndDuplicateErrors(t *testing.T) {
	tenantID := uuid.New()
	s := &Service{repo: &invitationOpsRepoStub{}, settings: fakeSettings{}}

	_, err := s.AdminCreateUser(context.Background(), domain.AdminCreateUserInput{TenantID: tenantID, Email: "", Password: ""})
	if err == nil || err.Error() != "email and password are required" {
		t.Fatalf("expected email/password required error, got %v", err)
	}

	_, err = s.AdminCreateUser(context.Background(), domain.AdminCreateUserInput{TenantID: tenantID, Email: "u@example.com", Password: "short"})
	if err == nil || err.Error() == "" {
		t.Fatalf("expected password policy violation error, got %v", err)
	}

	repo := &invitationOpsRepoStub{identityByEM: domain.AuthIdentity{ID: uuid.New(), TenantID: tenantID, Email: "u@example.com"}}
	s = &Service{repo: repo, settings: fakeSettings{}}
	_, err = s.AdminCreateUser(context.Background(), domain.AdminCreateUserInput{TenantID: tenantID, Email: "u@example.com", Password: "Password!123"})
	if err == nil || err.Error() != "user with this email already exists in tenant" {
		t.Fatalf("expected duplicate-user error, got %v", err)
	}
}

func TestService_AdminCreateUser_Success_NormalizationAndRoleAssignment(t *testing.T) {
	tenantID := uuid.New()
	repo := &invitationOpsRepoStub{
		identityErr: errors.New("not found"),
		roleByName:  domain.Role{ID: uuid.New(), Name: "admin"},
		userOut:     domain.User{ID: uuid.New(), FirstName: "F", LastName: "L", Roles: []string{"admin", "member"}, EmailVerified: true, IsActive: true, CreatedAt: time.Now()},
	}
	s := &Service{
		repo:     repo,
		settings: fakeSettings{strings: map[string]string{}},
		pub:      publisherFunc(func(context.Context, evdomain.Event) error { return nil }),
	}

	user, err := s.AdminCreateUser(context.Background(), domain.AdminCreateUserInput{
		TenantID:      tenantID,
		Email:         "  USER@Example.com ",
		Password:      "Password!123",
		FirstName:     "F",
		LastName:      "L",
		Roles:         []string{" Admin ", "member", "ADMIN", ""},
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("AdminCreateUser unexpected err=%v", err)
	}
	if user.ID == uuid.Nil {
		t.Fatal("expected created user")
	}
	if repo.lookupEmail != "user@example.com" {
		t.Fatalf("expected normalized lookup email, got %q", repo.lookupEmail)
	}
	if repo.setEmailVerifiedN != 1 {
		t.Fatalf("expected SetUserEmailVerified once, got %d", repo.setEmailVerifiedN)
	}
	if repo.addUserRoleN != 2 {
		t.Fatalf("expected exactly 2 normalized unique role assignments, got %d", repo.addUserRoleN)
	}
}

func TestInvitationTxWrappers_BeginRunCommitBranches(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	authID := uuid.New()

	t.Run("acceptInvitationTx begin and run/commit branches", func(t *testing.T) {
		s := &Service{}
		inv := domain.Invitation{ID: uuid.New(), TenantID: &tenantID, Email: "u@example.com", Role: "admin", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
		in := domain.AcceptInvitationInput{Token: "tok", Password: "Password!123", FirstName: "U", LastName: "Ser"}

		beginErrRepo := &txInvitationRepoStub{invitationOpsRepoStub: &invitationOpsRepoStub{}, tx: &txStub{}, txRepo: &invitationOpsRepoStub{}, beginErr: errors.New("begin failed")}
		s.repo = beginErrRepo
		if err := s.acceptInvitationTx(context.Background(), userID, authID, inv, in, []string{"admin"}, "hash", "tokenHash"); err == nil {
			t.Fatal("expected begin tx error")
		}

		runErrInner := &invitationOpsRepoStub{acceptErr: errors.New("accept failed")}
		txRunErr := &txStub{}
		runErrRepo := &txInvitationRepoStub{invitationOpsRepoStub: &invitationOpsRepoStub{}, tx: txRunErr, txRepo: runErrInner}
		s.repo = runErrRepo
		if err := s.acceptInvitationTx(context.Background(), userID, authID, inv, in, []string{"admin"}, "hash", "tokenHash"); err == nil {
			t.Fatal("expected runAcceptInvitationOps error")
		}
		if txRunErr.commitN != 0 || txRunErr.rollbackN == 0 {
			t.Fatalf("expected rollback-only on run error, got commit=%d rollback=%d", txRunErr.commitN, txRunErr.rollbackN)
		}

		commitErrInner := &invitationOpsRepoStub{acceptID: uuid.New(), roleByName: domain.Role{ID: uuid.New(), Name: "admin"}}
		txCommitErr := &txStub{commitErr: errors.New("commit failed")}
		commitErrRepo := &txInvitationRepoStub{invitationOpsRepoStub: &invitationOpsRepoStub{}, tx: txCommitErr, txRepo: commitErrInner}
		s.repo = commitErrRepo
		if err := s.acceptInvitationTx(context.Background(), userID, authID, inv, in, []string{"admin"}, "hash", "tokenHash"); err == nil {
			t.Fatal("expected commit error")
		}
		if txCommitErr.commitN != 1 {
			t.Fatalf("expected one commit on commit-error branch, got %d", txCommitErr.commitN)
		}

		successInner := &invitationOpsRepoStub{acceptID: uuid.New(), roleByName: domain.Role{ID: uuid.New(), Name: "admin"}}
		txSuccess := &txStub{}
		successRepo := &txInvitationRepoStub{invitationOpsRepoStub: &invitationOpsRepoStub{}, tx: txSuccess, txRepo: successInner}
		s.repo = successRepo
		if err := s.acceptInvitationTx(context.Background(), userID, authID, inv, in, []string{"admin"}, "hash", "tokenHash"); err != nil {
			t.Fatalf("expected successful acceptInvitationTx, got %v", err)
		}
		if txSuccess.commitN != 1 {
			t.Fatalf("expected one commit, got %d", txSuccess.commitN)
		}
	})

	t.Run("adminCreateUserTx begin and run/commit branches", func(t *testing.T) {
		s := &Service{}
		in := domain.AdminCreateUserInput{TenantID: tenantID, Email: "u@example.com", Password: "Password!123", Roles: []string{"admin"}}

		beginErrRepo := &txInvitationRepoStub{invitationOpsRepoStub: &invitationOpsRepoStub{}, tx: &txStub{}, txRepo: &invitationOpsRepoStub{}, beginErr: errors.New("begin failed")}
		s.repo = beginErrRepo
		if err := s.adminCreateUserTx(context.Background(), userID, authID, in, []string{"admin"}, "hash"); err == nil {
			t.Fatal("expected begin tx error")
		}

		runErrInner := &invitationOpsRepoStub{roleErr: errors.New("missing role")}
		txRunErr := &txStub{}
		runErrRepo := &txInvitationRepoStub{invitationOpsRepoStub: &invitationOpsRepoStub{}, tx: txRunErr, txRepo: runErrInner}
		s.repo = runErrRepo
		if err := s.adminCreateUserTx(context.Background(), userID, authID, in, []string{"admin"}, "hash"); err == nil {
			t.Fatal("expected runAdminCreateUserOps error")
		}
		if txRunErr.commitN != 0 || txRunErr.rollbackN == 0 {
			t.Fatalf("expected rollback-only on run error, got commit=%d rollback=%d", txRunErr.commitN, txRunErr.rollbackN)
		}

		commitErrInner := &invitationOpsRepoStub{roleByName: domain.Role{ID: uuid.New(), Name: "admin"}}
		txCommitErr := &txStub{commitErr: errors.New("commit failed")}
		commitErrRepo := &txInvitationRepoStub{invitationOpsRepoStub: &invitationOpsRepoStub{}, tx: txCommitErr, txRepo: commitErrInner}
		s.repo = commitErrRepo
		if err := s.adminCreateUserTx(context.Background(), userID, authID, in, []string{"admin"}, "hash"); err == nil {
			t.Fatal("expected commit error")
		}
		if txCommitErr.commitN != 1 {
			t.Fatalf("expected one commit on commit-error branch, got %d", txCommitErr.commitN)
		}

		successInner := &invitationOpsRepoStub{roleByName: domain.Role{ID: uuid.New(), Name: "admin"}}
		txSuccess := &txStub{}
		successRepo := &txInvitationRepoStub{invitationOpsRepoStub: &invitationOpsRepoStub{}, tx: txSuccess, txRepo: successInner}
		s.repo = successRepo
		if err := s.adminCreateUserTx(context.Background(), userID, authID, in, []string{"admin"}, "hash"); err != nil {
			t.Fatalf("expected successful adminCreateUserTx, got %v", err)
		}
		if txSuccess.commitN != 1 {
			t.Fatalf("expected one commit, got %d", txSuccess.commitN)
		}
	})
}
