package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	edomain "github.com/corvusHold/guard/internal/email/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

type fakeEmail struct{ lastBody string }

func TestHTTP_Authorize_AllowAndDeny(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-authz-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name, nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// wire services and http
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Sign up user via HTTP to obtain tokens
	email := "user.authz.itest@example.com"
	password := "Password!123"
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var toks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&toks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if toks.AccessToken == "" {
		t.Fatalf("expected access token")
	}

	// Resolve user id from token
	intr, err := auth.Introspect(ctx, toks.AccessToken)
	if err != nil || !intr.Active {
		t.Fatalf("introspect failed: %v", err)
	}

	// FGA setup via service: create group, add user, grant read
	grp, err := auth.CreateGroup(ctx, tenantID, "engineering", "eng group")
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := auth.AddGroupMember(ctx, grp.ID, intr.UserID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if _, err := auth.CreateACLTuple(ctx, tenantID, "group", grp.ID, "settings:read", "tenant", nil, nil); err != nil {
		t.Fatalf("create acl tuple: %v", err)
	}

	// POST /v1/auth/authorize -> allowed=true
	allowBody := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "self",
		"permission_key": "settings:read",
		"object_type":    "tenant",
	}
	ab, _ := json.Marshal(allowBody)
	areq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(ab))
	areq.Header.Set("Content-Type", "application/json")
	areq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	arec := httptest.NewRecorder()
	e.ServeHTTP(arec, areq)
	if arec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", arec.Code, arec.Body.String())
	}
	var allowResp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(arec.Body.Bytes())).Decode(&allowResp); err != nil {
		t.Fatalf("decode allow resp: %v", err)
	}
	if !allowResp.Allowed {
		t.Fatalf("expected allowed=true, got: %s", arec.Body.String())
	}

	// POST /v1/auth/authorize with explicit user subject -> allowed=true
	uBody := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "user",
		"subject_id":     intr.UserID.String(),
		"permission_key": "settings:read",
		"object_type":    "tenant",
	}
	ub, _ := json.Marshal(uBody)
	ureq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(ub))
	ureq.Header.Set("Content-Type", "application/json")
	ureq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	urec := httptest.NewRecorder()
	e.ServeHTTP(urec, ureq)
	if urec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", urec.Code, urec.Body.String())
	}
	var uresp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(urec.Body.Bytes())).Decode(&uresp); err != nil {
		t.Fatalf("decode user resp: %v", err)
	}
	if !uresp.Allowed {
		t.Fatalf("expected allowed=true for explicit user, got: %s", urec.Body.String())
	}

	// POST /v1/auth/authorize with group subject -> allowed=true
	gBody := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "group",
		"subject_id":     grp.ID.String(),
		"permission_key": "settings:read",
		"object_type":    "tenant",
	}
	gb, _ := json.Marshal(gBody)
	greq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(gb))
	greq.Header.Set("Content-Type", "application/json")
	greq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	grec := httptest.NewRecorder()
	e.ServeHTTP(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", grec.Code, grec.Body.String())
	}
	var gresp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(grec.Body.Bytes())).Decode(&gresp); err != nil {
		t.Fatalf("decode group resp: %v", err)
	}
	if !gresp.Allowed {
		t.Fatalf("expected allowed=true for group subject, got: %s", grec.Body.String())
	}

	// Negative: subject_type=user but missing subject_id -> 400
	missBody := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "user",
		"permission_key": "settings:read",
		"object_type":    "tenant",
	}
	mb, _ := json.Marshal(missBody)
	mreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(mb))
	mreq.Header.Set("Content-Type", "application/json")
	mreq.Header.Set("X-Auth-Mode", "bearer")
	mreq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	mrec := httptest.NewRecorder()
	e.ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing subject_id, got %d: %s", mrec.Code, mrec.Body.String())
	}

	// Negative: invalid subject_type -> 400 (unsupported subject_type)
	ivBody := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "invalid",
		"subject_id":     intr.UserID.String(),
		"permission_key": "settings:read",
		"object_type":    "tenant",
	}
	ivb, _ := json.Marshal(ivBody)
	ivreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(ivb))
	ivreq.Header.Set("Content-Type", "application/json")
	ivreq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	ivrec := httptest.NewRecorder()
	e.ServeHTTP(ivrec, ivreq)
	if ivrec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid subject_type, got %d: %s", ivrec.Code, ivrec.Body.String())
	}

	// POST /v1/auth/authorize with a permission not granted -> allowed=false
	denyBody := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "self",
		"permission_key": "settings:write",
		"object_type":    "tenant",
	}
	dbb, _ := json.Marshal(denyBody)
	dreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(dbb))
	dreq.Header.Set("Content-Type", "application/json")
	dreq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	drec := httptest.NewRecorder()
	e.ServeHTTP(drec, dreq)
	if drec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", drec.Code, drec.Body.String())
	}
	var denyResp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(drec.Body.Bytes())).Decode(&denyResp); err != nil {
		t.Fatalf("decode deny resp: %v", err)
	}
	if denyResp.Allowed {
		t.Fatalf("expected allowed=false, got: %s", drec.Body.String())
	}

	// Cleanup tuple and verify read now denied
	if err := auth.DeleteACLTuple(ctx, tenantID, "group", grp.ID, "settings:read", "tenant", nil); err != nil {
		t.Fatalf("delete acl tuple: %v", err)
	}
	// self read should now be denied
	areq2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(ab))
	areq2.Header.Set("Content-Type", "application/json")
	areq2.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	arec2 := httptest.NewRecorder()
	e.ServeHTTP(arec2, areq2)
	if arec2.Code != http.StatusOK {
		t.Fatalf("expected 200 after tuple delete, got %d: %s", arec2.Code, arec2.Body.String())
	}
	var allowResp2 struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(arec2.Body.Bytes())).Decode(&allowResp2); err != nil {
		t.Fatalf("decode allow2 resp: %v", err)
	}
	if allowResp2.Allowed {
		t.Fatalf("expected allowed=false after tuple delete, got: %s", arec2.Body.String())
	}

	// Final cleanup: remove membership and delete group
	if err := auth.RemoveGroupMember(ctx, grp.ID, intr.UserID); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if err := auth.DeleteGroup(ctx, grp.ID, tenantID); err != nil {
		t.Fatalf("delete group: %v", err)
	}
}

// Edge cases:
// - Object-scoped grant (specific object_id) vs different object_id and no object_id
// - Type-scoped grant (object_type only) should allow any object_id of that type
// - Cross-tenant deny (using a different tenant_id than where grants exist)
func TestHTTP_Authorize_ObjectScopeAndCrossTenant(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenants A and B
	tr := trepo.New(pool)
	tenantA := uuid.New()
	if err := tr.Create(ctx, tenantA, "http-authz-obj-"+tenantA.String(), nil); err != nil {
		t.Fatalf("create tenantA: %v", err)
	}
	tenantB := uuid.New()
	if err := tr.Create(ctx, tenantB, "http-authz-obj-"+tenantB.String(), nil); err != nil {
		t.Fatalf("create tenantB: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// wire services and http
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Sign up a user in tenant A
	email := "user.authz.obj@example.com"
	password := "Password!123"
	sBody := map[string]string{
		"tenant_id": tenantA.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var toks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&toks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if toks.AccessToken == "" {
		t.Fatalf("expected access token")
	}

	// Resolve user id from token
	intr, err := auth.Introspect(ctx, toks.AccessToken)
	if err != nil || !intr.Active {
		t.Fatalf("introspect failed: %v", err)
	}

	// 1) Object-specific grant: users:read on object_type "user" for a single object_id
	objID := uuid.New().String()
	if _, err := auth.CreateACLTuple(ctx, tenantA, "user", intr.UserID, "users:read", "user", &objID, nil); err != nil {
		t.Fatalf("create object-specific acl: %v", err)
	}
	// Allowed for that exact object_id
	a1 := map[string]string{
		"tenant_id":      tenantA.String(),
		"subject_type":   "self",
		"permission_key": "users:read",
		"object_type":    "user",
		"object_id":      objID,
	}
	a1b, _ := json.Marshal(a1)
	a1req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(a1b))
	a1req.Header.Set("Content-Type", "application/json")
	a1req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	a1rec := httptest.NewRecorder()
	e.ServeHTTP(a1rec, a1req)
	if a1rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", a1rec.Code, a1rec.Body.String())
	}
	var a1resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(a1rec.Body.Bytes())).Decode(&a1resp); err != nil {
		t.Fatalf("decode a1: %v", err)
	}
	if !a1resp.Allowed {
		t.Fatalf("expected allowed=true for object-specific grant, got: %s", a1rec.Body.String())
	}

	// Denied for a different object_id
	objID2 := uuid.New().String()
	a2 := map[string]string{
		"tenant_id":      tenantA.String(),
		"subject_type":   "self",
		"permission_key": "users:read",
		"object_type":    "user",
		"object_id":      objID2,
	}
	a2b, _ := json.Marshal(a2)
	a2req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(a2b))
	a2req.Header.Set("Content-Type", "application/json")
	a2req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	a2rec := httptest.NewRecorder()
	e.ServeHTTP(a2rec, a2req)
	if a2rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", a2rec.Code, a2rec.Body.String())
	}
	var a2resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(a2rec.Body.Bytes())).Decode(&a2resp); err != nil {
		t.Fatalf("decode a2: %v", err)
	}
	if a2resp.Allowed {
		t.Fatalf("expected allowed=false for different object_id, got: %s", a2rec.Body.String())
	}

	// Denied with no object_id (requires unscoped type grant)
	a3 := map[string]string{
		"tenant_id":      tenantA.String(),
		"subject_type":   "self",
		"permission_key": "users:read",
		"object_type":    "user",
	}
	a3b, _ := json.Marshal(a3)
	a3req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(a3b))
	a3req.Header.Set("Content-Type", "application/json")
	a3req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	a3rec := httptest.NewRecorder()
	e.ServeHTTP(a3rec, a3req)
	if a3rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", a3rec.Code, a3rec.Body.String())
	}
	var a3resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(a3rec.Body.Bytes())).Decode(&a3resp); err != nil {
		t.Fatalf("decode a3: %v", err)
	}
	if a3resp.Allowed {
		t.Fatalf("expected allowed=false for missing object_id with only object-specific grant, got: %s", a3rec.Body.String())
	}

	// Cleanup object-specific grant
	if err := auth.DeleteACLTuple(ctx, tenantA, "user", intr.UserID, "users:read", "user", &objID); err != nil {
		t.Fatalf("delete object-specific acl: %v", err)
	}

	// 2) Type-scoped grant: users:read on type "user" (no object_id) should allow any object_id of that type
	if _, err := auth.CreateACLTuple(ctx, tenantA, "user", intr.UserID, "users:read", "user", nil, nil); err != nil {
		t.Fatalf("create type-scoped acl: %v", err)
	}
	a4 := map[string]string{
		"tenant_id":      tenantA.String(),
		"subject_type":   "self",
		"permission_key": "users:read",
		"object_type":    "user",
		"object_id":      objID2,
	}
	a4b, _ := json.Marshal(a4)
	a4req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(a4b))
	a4req.Header.Set("Content-Type", "application/json")
	a4req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	a4rec := httptest.NewRecorder()
	e.ServeHTTP(a4rec, a4req)
	if a4rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", a4rec.Code, a4rec.Body.String())
	}
	var a4resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(a4rec.Body.Bytes())).Decode(&a4resp); err != nil {
		t.Fatalf("decode a4: %v", err)
	}
	if !a4resp.Allowed {
		t.Fatalf("expected allowed=true for type-scoped grant, got: %s", a4rec.Body.String())
	}

	// 3) Cross-tenant deny: using tenant B with no grants should deny
	ct := map[string]string{
		"tenant_id":      tenantB.String(),
		"subject_type":   "self",
		"permission_key": "users:read",
		"object_type":    "user",
	}
	ctb, _ := json.Marshal(ct)
	ctreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(ctb))
	ctreq.Header.Set("Content-Type", "application/json")
	ctreq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	ctrec := httptest.NewRecorder()
	e.ServeHTTP(ctrec, ctreq)
	if ctrec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", ctrec.Code, ctrec.Body.String())
	}
	var ctresp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(ctrec.Body.Bytes())).Decode(&ctresp); err != nil {
		t.Fatalf("decode cross-tenant: %v", err)
	}
	if ctresp.Allowed {
		t.Fatalf("expected allowed=false for cross-tenant check, got: %s", ctrec.Body.String())
	}

	// Cleanup type-scoped grant
	if err := auth.DeleteACLTuple(ctx, tenantA, "user", intr.UserID, "users:read", "user", nil); err != nil {
		t.Fatalf("delete type-scoped acl: %v", err)
	}
}

func TestHTTP_Password_Signup_Login_Refresh_AuditAndClaims(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-password-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name, nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// wire services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	// capture audit events
	events := make([]evdomain.Event, 0, 3)
	auth.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error {
		events = append(events, e)
		return nil
	}))
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	email := "user.pass.itest@example.com"
	password := "Password!123"

	// POST /v1/auth/password/signup
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var stoks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&stoks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if stoks.AccessToken == "" || stoks.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens: %+v", stoks)
	}
	// iss/aud
	sparts := strings.Split(stoks.AccessToken, ".")
	if len(sparts) < 2 {
		t.Fatalf("invalid jwt format")
	}
	spayload, err := base64.RawURLEncoding.DecodeString(sparts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var sclaims map[string]any
	if err := json.Unmarshal(spayload, &sclaims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if iss, _ := sclaims["iss"].(string); iss != cfg.PublicBaseURL {
		t.Fatalf("iss mismatch: expected %s, got %v", cfg.PublicBaseURL, sclaims["iss"])
	}
	if aud, _ := sclaims["aud"].(string); aud != cfg.PublicBaseURL {
		t.Fatalf("aud mismatch: expected %s, got %v", cfg.PublicBaseURL, sclaims["aud"])
	}

	// POST /v1/auth/password/login
	lBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	lb, _ := json.Marshal(lBody)
	lreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(lb))
	lreq.Header.Set("Content-Type", "application/json")
	lreq.Header.Set("X-Auth-Mode", "bearer")
	lreq.Header.Set("User-Agent", "itest-agent")
	lrec := httptest.NewRecorder()
	e.ServeHTTP(lrec, lreq)
	if lrec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", lrec.Code, lrec.Body.String())
	}
	var ltoks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(lrec.Body.Bytes())).Decode(&ltoks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if ltoks.AccessToken == "" || ltoks.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens: %+v", ltoks)
	}
	// iss/aud
	lparts := strings.Split(ltoks.AccessToken, ".")
	if len(lparts) < 2 {
		t.Fatalf("invalid jwt format")
	}
	lpayload, err := base64.RawURLEncoding.DecodeString(lparts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var lclaims map[string]any
	if err := json.Unmarshal(lpayload, &lclaims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if iss, _ := lclaims["iss"].(string); iss != cfg.PublicBaseURL {
		t.Fatalf("iss mismatch: expected %s, got %v", cfg.PublicBaseURL, lclaims["iss"])
	}
	if aud, _ := lclaims["aud"].(string); aud != cfg.PublicBaseURL {
		t.Fatalf("aud mismatch: expected %s, got %v", cfg.PublicBaseURL, lclaims["aud"])
	}

	// Assert audit event for password login
	foundLogin := false
	for _, ev := range events {
		if ev.Type == "auth.password.login.success" {
			if ev.Meta["provider"] != "password" {
				t.Fatalf("provider mismatch: %v", ev.Meta["provider"])
			}
			if ev.Meta["email"] != email {
				t.Fatalf("email mismatch: %v", ev.Meta["email"])
			}
			foundLogin = true
		}
	}
	if !foundLogin {
		t.Fatalf("expected auth.password.login.success event")
	}

	// POST /v1/auth/refresh
	rBody := map[string]string{
		"refresh_token": ltoks.RefreshToken,
	}
	rb, _ := json.Marshal(rBody)
	rreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(rb))
	rreq.Header.Set("Content-Type", "application/json")
	rreq.Header.Set("X-Auth-Mode", "bearer")
	rrec := httptest.NewRecorder()
	e.ServeHTTP(rrec, rreq)
	if rrec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rrec.Code, rrec.Body.String())
	}
	var rtoks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(rrec.Body.Bytes())).Decode(&rtoks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if rtoks.AccessToken == "" || rtoks.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens: %+v", rtoks)
	}
	// Assert refresh audit event
	foundRefresh := false
	for _, ev := range events {
		if ev.Type == "auth.token.refresh.success" {
			foundRefresh = true
		}
	}
	if !foundRefresh {
		t.Fatalf("expected auth.token.refresh.success event")
	}
}

func (f *fakeEmail) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	f.lastBody = body
	return nil
}

var _ edomain.Sender = (*fakeEmail)(nil)

type tokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// publisherFunc helps implement evdomain.Publisher in tests via a func.
type publisherFunc func(ctx context.Context, e evdomain.Event) error

func (f publisherFunc) Publish(ctx context.Context, e evdomain.Event) error { return f(ctx, e) }

// Group subject with object-scoped and type-scoped permissions
func TestHTTP_Authorize_Group_ObjectAndTypeScope(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "http-authz-group-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// wire services and http
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Sign up a user to obtain a token (any authenticated user can call authorize)
	email := "group.scope.itest@example.com"
	password := "Password!123"
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var toks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&toks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if toks.AccessToken == "" {
		t.Fatalf("expected access token")
	}

	// Create group and object-scoped grant for the group
	grp, err := auth.CreateGroup(ctx, tenantID, "qa", "qa group")
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	perm := "docs:read"
	otype := "doc"
	oid := uuid.New().String()
	if _, err := auth.CreateACLTuple(ctx, tenantID, "group", grp.ID, perm, otype, &oid, nil); err != nil {
		t.Fatalf("create group object-scoped acl: %v", err)
	}

	// Allowed for exact object_id
	a1 := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "group",
		"subject_id":     grp.ID.String(),
		"permission_key": perm,
		"object_type":    otype,
		"object_id":      oid,
	}
	a1b, _ := json.Marshal(a1)
	a1req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(a1b))
	a1req.Header.Set("Content-Type", "application/json")
	a1req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	a1rec := httptest.NewRecorder()
	e.ServeHTTP(a1rec, a1req)
	if a1rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", a1rec.Code, a1rec.Body.String())
	}
	var a1resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(a1rec.Body.Bytes())).Decode(&a1resp); err != nil {
		t.Fatalf("decode a1: %v", err)
	}
	if !a1resp.Allowed {
		t.Fatalf("expected allowed=true for group object-scoped grant")
	}

	// Denied for different object_id
	oid2 := uuid.New().String()
	a2 := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "group",
		"subject_id":     grp.ID.String(),
		"permission_key": perm,
		"object_type":    otype,
		"object_id":      oid2,
	}
	a2b, _ := json.Marshal(a2)
	a2req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(a2b))
	a2req.Header.Set("Content-Type", "application/json")
	a2req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	a2rec := httptest.NewRecorder()
	e.ServeHTTP(a2rec, a2req)
	if a2rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", a2rec.Code, a2rec.Body.String())
	}
	var a2resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(a2rec.Body.Bytes())).Decode(&a2resp); err != nil {
		t.Fatalf("decode a2: %v", err)
	}
	if a2resp.Allowed {
		t.Fatalf("expected allowed=false for different object_id")
	}

	// Denied when omitting object_id (only object-scoped grant exists)
	a3 := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "group",
		"subject_id":     grp.ID.String(),
		"permission_key": perm,
		"object_type":    otype,
	}
	a3b, _ := json.Marshal(a3)
	a3req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(a3b))
	a3req.Header.Set("Content-Type", "application/json")
	a3req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	a3rec := httptest.NewRecorder()
	e.ServeHTTP(a3rec, a3req)
	if a3rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", a3rec.Code, a3rec.Body.String())
	}
	var a3resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(a3rec.Body.Bytes())).Decode(&a3resp); err != nil {
		t.Fatalf("decode a3: %v", err)
	}
	if a3resp.Allowed {
		t.Fatalf("expected allowed=false when missing object_id with only object-scoped grant")
	}

	// Cleanup object-specific grant
	if err := auth.DeleteACLTuple(ctx, tenantID, "group", grp.ID, perm, otype, &oid); err != nil {
		t.Fatalf("delete group object-scoped acl: %v", err)
	}

	// Type-scoped grant for the group (no object_id)
	if _, err := auth.CreateACLTuple(ctx, tenantID, "group", grp.ID, perm, otype, nil, nil); err != nil {
		t.Fatalf("create group type-scoped acl: %v", err)
	}
	// Allowed for any object_id of that type
	a4 := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "group",
		"subject_id":     grp.ID.String(),
		"permission_key": perm,
		"object_type":    otype,
		"object_id":      oid2,
	}
	a4b, _ := json.Marshal(a4)
	a4req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(a4b))
	a4req.Header.Set("Content-Type", "application/json")
	a4req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	a4rec := httptest.NewRecorder()
	e.ServeHTTP(a4rec, a4req)
	if a4rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", a4rec.Code, a4rec.Body.String())
	}
	var a4resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(a4rec.Body.Bytes())).Decode(&a4resp); err != nil {
		t.Fatalf("decode a4: %v", err)
	}
	if !a4resp.Allowed {
		t.Fatalf("expected allowed=true for group type-scoped grant")
	}

	// Also allowed when omitting object_id (global for that type)
	a5 := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "group",
		"subject_id":     grp.ID.String(),
		"permission_key": perm,
		"object_type":    otype,
	}
	a5b, _ := json.Marshal(a5)
	a5req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(a5b))
	a5req.Header.Set("Content-Type", "application/json")
	a5req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	a5rec := httptest.NewRecorder()
	e.ServeHTTP(a5rec, a5req)
	if a5rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", a5rec.Code, a5rec.Body.String())
	}
	var a5resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(a5rec.Body.Bytes())).Decode(&a5resp); err != nil {
		t.Fatalf("decode a5: %v", err)
	}
	if !a5resp.Allowed {
		t.Fatalf("expected allowed=true for group type-scoped grant without object_id")
	}

	// Cleanup
	if err := auth.DeleteACLTuple(ctx, tenantID, "group", grp.ID, perm, otype, nil); err != nil {
		t.Fatalf("delete group type-scoped acl: %v", err)
	}
	if err := auth.DeleteGroup(ctx, grp.ID, tenantID); err != nil {
		t.Fatalf("delete group: %v", err)
	}
}

// Wildcard object_type grants: allow any object_type/object_id
func TestHTTP_Authorize_WildcardObjectType(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "http-authz-wildcard-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Signup user and grant wildcard permission
	email := "wildcard.itest@example.com"
	password := "Password!123"
	sb, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "email": email, "password": password})
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var toks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&toks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	intr, err := auth.Introspect(ctx, toks.AccessToken)
	if err != nil || !intr.Active {
		t.Fatalf("introspect failed: %v", err)
	}

	// wildcard grant
	perm := "reports:read"
	if _, err := auth.CreateACLTuple(ctx, tenantID, "user", intr.UserID, perm, "*", nil, nil); err != nil {
		t.Fatalf("create wildcard acl: %v", err)
	}

	// Allow for any object_type/object_id
	for _, ot := range []string{"report", "invoice", "tenant"} {
		body := map[string]string{
			"tenant_id":      tenantID.String(),
			"subject_type":   "self",
			"permission_key": perm,
			"object_type":    ot,
			"object_id":      uuid.New().String(),
		}
		bb, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(bb))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d: %s", ot, rec.Code, rec.Body.String())
		}
		var rsp struct {
			Allowed bool `json:"allowed"`
		}
		if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&rsp); err != nil {
			t.Fatalf("decode resp: %v", err)
		}
		if !rsp.Allowed {
			t.Fatalf("expected allowed=true for wildcard on %s", ot)
		}
	}

	// Also allow when omitting object_id
	body2 := map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "self",
		"permission_key": perm,
		"object_type":    "anything",
	}
	b2, _ := json.Marshal(body2)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(b2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var rsp2 struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(rec2.Body.Bytes())).Decode(&rsp2); err != nil {
		t.Fatalf("decode resp2: %v", err)
	}
	if !rsp2.Allowed {
		t.Fatalf("expected allowed=true for wildcard without object_id")
	}

	// Cleanup
	if err := auth.DeleteACLTuple(ctx, tenantID, "user", intr.UserID, perm, "*", nil); err != nil {
		t.Fatalf("delete wildcard acl: %v", err)
	}
}

// Negative input validation: invalid tenant_id, invalid subject_id, missing object_type
func TestHTTP_Authorize_Negative_InvalidInputs(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "http-authz-neg-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	sb, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "email": "neg.itest@example.com", "password": "Password!123"})
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var toks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&toks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}

	// invalid tenant_id UUID -> 400
	b1, _ := json.Marshal(map[string]string{
		"tenant_id":      "not-a-uuid",
		"subject_type":   "self",
		"permission_key": "x:y",
		"object_type":    "z",
	})
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(b1))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid tenant_id, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// invalid subject_id UUID when subject_type=user -> 400
	b2, _ := json.Marshal(map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "user",
		"subject_id":     "bad-uuid",
		"permission_key": "x:y",
		"object_type":    "z",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(b2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid subject_id, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// missing object_type -> 400
	b3, _ := json.Marshal(map[string]string{
		"tenant_id":      tenantID.String(),
		"subject_type":   "self",
		"permission_key": "x:y",
	})
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(b3))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	rec3 := httptest.NewRecorder()
	e.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing object_type, got %d: %s", rec3.Code, rec3.Body.String())
	}
}

// Combined grants: object-specific and type-scoped for same permission/type -> allow regardless of object_id
func TestHTTP_Authorize_CombinedGrants(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "http-authz-combined-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Signup user
	sb, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "email": "combined.itest@example.com", "password": "Password!123"})
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var toks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&toks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	intr, err := auth.Introspect(ctx, toks.AccessToken)
	if err != nil || !intr.Active {
		t.Fatalf("introspect failed: %v", err)
	}

	perm := "files:read"
	otype := "file"
	oid1 := uuid.New().String()
	oid2 := uuid.New().String()
	// object-specific
	if _, err := auth.CreateACLTuple(ctx, tenantID, "user", intr.UserID, perm, otype, &oid1, nil); err != nil {
		t.Fatalf("create obj-specific: %v", err)
	}
	// type-scoped
	if _, err := auth.CreateACLTuple(ctx, tenantID, "user", intr.UserID, perm, otype, nil, nil); err != nil {
		t.Fatalf("create type-scoped: %v", err)
	}

	// Allowed with exact object_id
	b1, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "subject_type": "self", "permission_key": perm, "object_type": otype, "object_id": oid1})
	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(b1))
	r1.Header.Set("Content-Type", "application/json")
	r1.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w1.Code, w1.Body.String())
	}
	var p1 struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(w1.Body.Bytes())).Decode(&p1); err != nil {
		t.Fatalf("decode p1: %v", err)
	}
	if !p1.Allowed {
		t.Fatalf("expected allowed=true for combined grants (obj1)")
	}

	// Allowed with different object_id due to type-scoped
	b2, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "subject_type": "self", "permission_key": perm, "object_type": otype, "object_id": oid2})
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(b2))
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	var p2 struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(w2.Body.Bytes())).Decode(&p2); err != nil {
		t.Fatalf("decode p2: %v", err)
	}
	if !p2.Allowed {
		t.Fatalf("expected allowed=true for combined grants (obj2)")
	}

	// Allowed when omitting object_id due to type-scoped
	b3, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "subject_type": "self", "permission_key": perm, "object_type": otype})
	r3 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(b3))
	r3.Header.Set("Content-Type", "application/json")
	r3.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	w3 := httptest.NewRecorder()
	e.ServeHTTP(w3, r3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w3.Code, w3.Body.String())
	}
	var p3 struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(bytes.NewReader(w3.Body.Bytes())).Decode(&p3); err != nil {
		t.Fatalf("decode p3: %v", err)
	}
	if !p3.Allowed {
		t.Fatalf("expected allowed=true for combined grants (no object_id)")
	}

	// Cleanup
	if err := auth.DeleteACLTuple(ctx, tenantID, "user", intr.UserID, perm, otype, &oid1); err != nil {
		t.Fatalf("delete obj-specific: %v", err)
	}
	if err := auth.DeleteACLTuple(ctx, tenantID, "user", intr.UserID, perm, otype, nil); err != nil {
		t.Fatalf("delete type-scoped: %v", err)
	}
}

func TestHTTP_Magic_SendAndVerify(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-magic-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name, nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// wire services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	fe := &fakeEmail{}
	magic := svc.NewMagic(repo, cfg, settings, fe)
	auth := svc.New(repo, cfg, settings)
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// POST /v1/auth/magic/send
	body := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     "user.http.itest@example.com",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/magic/send", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if fe.lastBody == "" {
		t.Fatalf("expected email sent body captured")
	}

	// extract token
	re := regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)
	m := re.FindStringSubmatch(fe.lastBody)
	if len(m) < 2 {
		t.Fatalf("token not found in body: %q", fe.lastBody)
	}
	token := m[1]

	// GET /v1/auth/magic/verify
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/magic/verify?token="+token, nil)
	req2.Header.Set("X-Auth-Mode", "bearer")
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var trsp tokensResponse
	if err := json.NewDecoder(bytes.NewReader(rec2.Body.Bytes())).Decode(&trsp); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if trsp.AccessToken == "" || trsp.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens: %+v", trsp)
	}
}
