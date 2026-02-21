package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/keys"
	ssosvc "github.com/corvusHold/guard/internal/auth/sso/service"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

type ssoCallbackRepoStub struct {
	fakeRepo
	lookupErr error
	identity  domain.AuthIdentity
}

type ssoErrSettings struct {
	fakeSettings
	getStringErrKey string
}

type redisRESPStub struct {
	ln   net.Listener
	mu   sync.Mutex
	data map[string]string
}

func newRedisRESPStub(t *testing.T) *redisRESPStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen redis stub: %v", err)
	}
	s := &redisRESPStub{ln: ln, data: map[string]string{}}
	go s.serve()
	t.Cleanup(func() { _ = s.ln.Close() })
	return s
}

func (s *redisRESPStub) addr() string { return s.ln.Addr().String() }

func (s *redisRESPStub) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *redisRESPStub) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	for {
		args, err := readRESPArray(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			return
		}
		if len(args) == 0 {
			_ = writeSimple(conn, "OK")
			continue
		}
		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "PING", "CLIENT", "SELECT":
			_ = writeSimple(conn, "OK")
		case "COMMAND":
			_, _ = io.WriteString(conn, "*0\r\n")
		case "INFO":
			_ = writeBulk(conn, "# Server\nredis_version:7.0.0\n")
		case "HELLO":
			_ = writeMap(conn, map[string]string{
				"server":  "redis",
				"version": "7.0.0",
				"proto":   "3",
				"id":      "1",
				"mode":    "standalone",
				"role":    "master",
			})
		case "SET":
			if len(args) >= 3 {
				s.mu.Lock()
				s.data[args[1]] = args[2]
				s.mu.Unlock()
			}
			_ = writeSimple(conn, "OK")
		case "GET":
			if len(args) < 2 {
				_ = writeNil(conn)
				continue
			}
			s.mu.Lock()
			v, ok := s.data[args[1]]
			s.mu.Unlock()
			if !ok {
				_ = writeNil(conn)
				continue
			}
			_ = writeBulk(conn, v)
		case "EVAL":
			// We only need GET+DEL semantics used by callbackWorkOS.
			if len(args) >= 4 {
				key := args[3]
				s.mu.Lock()
				v, ok := s.data[key]
				if ok {
					delete(s.data, key)
				}
				s.mu.Unlock()
				if !ok {
					_ = writeNil(conn)
				} else {
					_ = writeBulk(conn, v)
				}
				continue
			}
			_ = writeNil(conn)
		default:
			_ = writeSimple(conn, "OK")
		}
	}
}

func readRESPArray(br *bufio.Reader) ([]string, error) {
	head, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	head = strings.TrimSpace(head)
	if head == "" {
		return nil, fmt.Errorf("invalid resp head: %q", head)
	}
	// Support inline commands (e.g. "PING" / "HELLO 3") used by some clients.
	if head[0] != '*' {
		return strings.Fields(head), nil
	}
	n, err := strconv.Atoi(head[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		lenLine, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		lenLine = strings.TrimSpace(lenLine)
		if len(lenLine) == 0 || lenLine[0] != '$' {
			return nil, fmt.Errorf("invalid bulk len: %q", lenLine)
		}
		l, err := strconv.Atoi(lenLine[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}

func writeSimple(w io.Writer, s string) error { _, err := io.WriteString(w, "+"+s+"\r\n"); return err }
func writeBulk(w io.Writer, s string) error {
	_, err := io.WriteString(w, fmt.Sprintf("$%d\r\n%s\r\n", len(s), s))
	return err
}
func writeNil(w io.Writer) error { _, err := io.WriteString(w, "$-1\r\n"); return err }
func writeMap(w io.Writer, m map[string]string) error {
	if _, err := io.WriteString(w, fmt.Sprintf("%%%d\r\n", len(m))); err != nil {
		return err
	}
	for k, v := range m {
		if err := writeBulk(w, k); err != nil {
			return err
		}
		if err := writeBulk(w, v); err != nil {
			return err
		}
	}
	return nil
}

func (s ssoErrSettings) GetString(ctx context.Context, key string, tenantID *uuid.UUID, def string) (string, error) {
	if key == s.getStringErrKey {
		return "", errors.New("settings failure")
	}
	return s.fakeSettings.GetString(ctx, key, tenantID, def)
}

func (r *ssoCallbackRepoStub) GetAuthIdentityByEmailTenant(context.Context, uuid.UUID, string) (domain.AuthIdentity, error) {
	if r.lookupErr != nil {
		return domain.AuthIdentity{}, r.lookupErr
	}
	return r.identity, nil
}

func TestSSO_NewSettersAndStartBranches_Extra(t *testing.T) {
	repo := &fakeRepo{}
	tenantID := uuid.New()
	cfg := config.Config{PublicBaseURL: "https://app.example"}

	s := NewSSO(repo, cfg, fakeSettings{})
	if s == nil || s.repo != repo {
		t.Fatalf("expected NewSSO wiring, got %#v", s)
	}

	s.SetPublisher(publisherFunc(func(context.Context, evdomain.Event) error { return nil }))
	s.SetLogger(zerolog.Nop())
	s.SetSSOProviderService(&ssosvc.SSOService{})
	km, err := keys.NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	s.SetKeyManager(km)
	if s.keyMgr != km {
		t.Fatal("expected SetKeyManager to assign manager")
	}

	if _, err := s.Start(context.Background(), domain.SSOStartInput{}); err == nil || err.Error() != "provider required" {
		t.Fatalf("expected provider required, got %v", err)
	}

	s.settings = fakeSettings{strings: map[string]string{}}
	s.keyMgr = nil
	if _, err := s.Start(context.Background(), domain.SSOStartInput{Provider: "google", TenantID: tenantID, RedirectURL: "https://app.example/return"}); err == nil || err.Error() != "asymmetric key manager required" {
		t.Fatalf("expected key manager required, got %v", err)
	}

	s.keyMgr = km
	s.settings = fakeSettings{strings: map[string]string{"sso.redirect_allowlist:" + tenantID.String(): "https://allowed.example/cb"}}
	if _, err := s.Start(context.Background(), domain.SSOStartInput{Provider: "google", TenantID: tenantID, RedirectURL: "not-a-url"}); err == nil || err.Error() != "redirect_url not allowed" {
		t.Fatalf("expected redirect allowlist rejection, got %v", err)
	}

	s.settings = fakeSettings{strings: map[string]string{}}
	url, err := s.Start(context.Background(), domain.SSOStartInput{Provider: "google", TenantID: tenantID, State: "abc"})
	if err != nil {
		t.Fatalf("Start unexpected err=%v", err)
	}
	if !strings.Contains(url, "/api/v1/auth/sso/google/callback") || !strings.Contains(url, "code=") {
		t.Fatalf("unexpected callback URL %q", url)
	}
}

func TestSSO_CallbackAndPortalAndRetry_ExtraBranches(t *testing.T) {
	t.Run("Callback dev-code missing-state bypass success", func(t *testing.T) {
		tenantID := uuid.New()
		s := NewSSO(&ssoCallbackRepoStub{lookupErr: errors.New("not found")}, config.Config{PublicBaseURL: "https://app.example"}, fakeSettings{strings: map[string]string{
			sdomain.KeySSOProvider + ":" + tenantID.String(): "dev",
		}})

		startURL, err := s.Start(context.Background(), domain.SSOStartInput{Provider: "google", TenantID: tenantID})
		if err != nil {
			t.Fatalf("Start unexpected err=%v", err)
		}
		u, err := url.Parse(startURL)
		if err != nil {
			t.Fatalf("parse start URL: %v", err)
		}
		code := u.Query().Get("code")
		if code == "" {
			t.Fatal("expected start URL code")
		}

		toks, err := s.Callback(context.Background(), domain.SSOCallbackInput{Provider: "google", Query: map[string][]string{"code": {code}}})
		if err != nil {
			t.Fatalf("Callback unexpected err=%v", err)
		}
		if toks.AccessToken == "" || toks.RefreshToken == "" {
			t.Fatalf("expected callback tokens, got %+v", toks)
		}
	})

	t.Run("Callback and callbackWorkOS missing/invalid state branches", func(t *testing.T) {
		s := NewSSO(&fakeRepo{}, config.Config{PublicBaseURL: "https://app.example", RedisAddr: "127.0.0.1:0"}, fakeSettings{})
		if _, err := s.Callback(context.Background(), domain.SSOCallbackInput{Provider: "google", Query: map[string][]string{}}); err == nil || err.Error() != "missing state" {
			t.Fatalf("expected missing state error, got %v", err)
		}
		if _, err := s.Callback(context.Background(), domain.SSOCallbackInput{Provider: "google", Query: map[string][]string{"state": {"s1"}}}); err == nil || err.Error() != "invalid state" {
			t.Fatalf("expected invalid state error, got %v", err)
		}

		if _, err := s.callbackWorkOS(context.Background(), domain.SSOCallbackInput{Provider: "workos", Query: map[string][]string{}}); err == nil || err.Error() != "missing state" {
			t.Fatalf("expected callbackWorkOS missing state error, got %v", err)
		}
		if _, err := s.callbackWorkOS(context.Background(), domain.SSOCallbackInput{Provider: "workos", Query: map[string][]string{"state": {"s1"}}}); err == nil || err.Error() != "invalid state" {
			t.Fatalf("expected callbackWorkOS invalid state error, got %v", err)
		}
	})

	t.Run("OrganizationPortalLinkGenerator early branches", func(t *testing.T) {
		tenantID := uuid.New()
		s := NewSSO(&fakeRepo{}, config.Config{PublicBaseURL: "https://app.example"}, fakeSettings{})

		if _, err := s.OrganizationPortalLinkGenerator(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "", TenantID: tenantID, CreatedBy: uuid.New()}); err == nil || err.Error() != "provider slug required" {
			t.Fatalf("expected provider slug required error, got %v", err)
		}

		if _, err := s.OrganizationPortalLinkGenerator(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "google", TenantID: tenantID, CreatedBy: uuid.New()}); err == nil || err.Error() != "sso service not initialized" {
			t.Fatalf("expected sso service not initialized error, got %v", err)
		}

		s.settings = fakeSettings{strings: map[string]string{sdomain.KeySSOProvider + ":" + tenantID.String(): "workos"}}
		if _, err := s.OrganizationPortalLinkGenerator(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "google", TenantID: tenantID, CreatedBy: uuid.New()}); err == nil || err.Error() != "provider not supported" {
			t.Fatalf("expected workos provider-not-supported error, got %v", err)
		}
	})

	t.Run("httpDoWithRetry retries 5xx then succeeds and build error", func(t *testing.T) {
		attempts := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("retry"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		defer ts.Close()

		resp, err := httpDoWithRetry(context.Background(), &http.Client{}, func() (*http.Request, error) {
			return http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
		})
		if err != nil {
			t.Fatalf("httpDoWithRetry unexpected err=%v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK || attempts != 3 {
			t.Fatalf("expected success on third attempt, got status=%d attempts=%d", resp.StatusCode, attempts)
		}

		if _, err := httpDoWithRetry(context.Background(), &http.Client{}, func() (*http.Request, error) {
			return nil, errors.New("build failed")
		}); err == nil {
			t.Fatal("expected build error")
		}
	})

	t.Run("startWorkOS and OrganizationPortalLinkGeneratorWorkOS early branches", func(t *testing.T) {
		tenantID := uuid.New()
		s := NewSSO(&fakeRepo{}, config.Config{PublicBaseURL: "https://app.example", RedisAddr: "127.0.0.1:0"}, fakeSettings{strings: map[string]string{}})

		if _, err := s.startWorkOS(context.Background(), domain.SSOStartInput{Provider: "workos", TenantID: tenantID}); err == nil || err.Error() != "workos client_id missing" {
			t.Fatalf("expected missing client_id error, got %v", err)
		}

		s.settings = ssoErrSettings{fakeSettings: fakeSettings{strings: map[string]string{}}, getStringErrKey: sdomain.KeyWorkOSClientID}
		if _, err := s.startWorkOS(context.Background(), domain.SSOStartInput{Provider: "workos", TenantID: tenantID}); err == nil {
			t.Fatal("expected workos client id settings error")
		}

		s.settings = fakeSettings{strings: map[string]string{
			sdomain.KeyWorkOSClientID + ":" + tenantID.String(): "client-123",
			sdomain.KeyPublicBaseURL + ":" + tenantID.String():  "https://app.example",
		}}
		if _, err := s.startWorkOS(context.Background(), domain.SSOStartInput{Provider: "workos", TenantID: tenantID, RedirectURL: "https://app.example/return"}); err == nil {
			t.Fatal("expected redis set failure path")
		}

		if _, err := s.OrganizationPortalLinkGeneratorWorkOS(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "dev", TenantID: tenantID, OrganizationID: "org_1"}); err == nil || err.Error() != "provider not supported" {
			t.Fatalf("expected provider not supported, got %v", err)
		}

		if _, err := s.OrganizationPortalLinkGeneratorWorkOS(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "workos", TenantID: tenantID}); err == nil || err.Error() != "organization ID not provided" {
			t.Fatalf("expected organization ID required, got %v", err)
		}

		s.settings = ssoErrSettings{fakeSettings: fakeSettings{strings: map[string]string{}}, getStringErrKey: sdomain.KeySSOProvider}
		if _, err := s.OrganizationPortalLinkGeneratorWorkOS(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "workos", TenantID: tenantID, OrganizationID: "org_1"}); err == nil {
			t.Fatal("expected get sso provider error")
		}

		s.settings = fakeSettings{strings: map[string]string{sdomain.KeySSOProvider + ":" + tenantID.String(): "dev"}}
		if _, err := s.OrganizationPortalLinkGeneratorWorkOS(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "workos", TenantID: tenantID, OrganizationID: "org_1"}); err == nil || err.Error() != "provider not workos" {
			t.Fatalf("expected provider mismatch error, got %v", err)
		}

		s.settings = fakeSettings{strings: map[string]string{sdomain.KeySSOProvider + ":" + tenantID.String(): "workos"}}
		if _, err := s.OrganizationPortalLinkGeneratorWorkOS(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "workos", TenantID: tenantID, OrganizationID: "org_1", Intent: "bad_intent"}); err == nil || err.Error() != "workos api key not configured" {
			t.Fatalf("expected api key missing error first, got %v", err)
		}

		s.settings = fakeSettings{strings: map[string]string{
			sdomain.KeySSOProvider + ":" + tenantID.String():      "workos",
			sdomain.KeyWorkOSAPIKey + ":" + tenantID.String():     "sk_test",
			sdomain.KeyWorkOSAPIBaseURL + ":" + tenantID.String(): "http://127.0.0.1:0",
		}}
		if _, err := s.OrganizationPortalLinkGeneratorWorkOS(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "workos", TenantID: tenantID, OrganizationID: "org_1", Intent: "bad_intent"}); err == nil || err.Error() != "intent not compatible with workos" {
			t.Fatalf("expected intent compatibility error, got %v", err)
		}

		if _, err := s.OrganizationPortalLinkGeneratorWorkOS(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "workos", TenantID: tenantID, OrganizationID: "org_1", Intent: "user_management"}); err == nil {
			t.Fatal("expected http transport error for workos portal generation")
		}
	})

	t.Run("startWorkOS callbackWorkOS and WorkOS portal success branches", func(t *testing.T) {
		tenantID := uuid.New()
		redisStub := newRedisRESPStub(t)
		repo := &ssoCallbackRepoStub{identity: domain.AuthIdentity{UserID: uuid.New(), TenantID: tenantID, Email: "u@example.com"}}

		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/sso/token":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"acc","profile":{"id":"p1","email":"u@example.com","first_name":"U","last_name":"Ser"}}`))
			case "/portal/generate_link":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"link":"https://portal.example/link"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer api.Close()

		s := NewSSO(repo, config.Config{PublicBaseURL: "https://app.example"}, fakeSettings{strings: map[string]string{
			sdomain.KeyWorkOSClientID + ":" + tenantID.String():              "client-1",
			sdomain.KeyWorkOSClientSecret + ":" + tenantID.String():          "secret-1",
			sdomain.KeyWorkOSAPIKey + ":" + tenantID.String():                "sk_test",
			sdomain.KeyWorkOSAPIBaseURL + ":" + tenantID.String():            api.URL,
			sdomain.KeySSOProvider + ":" + tenantID.String():                 "workos",
			sdomain.KeyPublicBaseURL + ":" + tenantID.String():               "https://app.example",
			sdomain.KeyWorkOSDefaultConnectionID + ":" + tenantID.String():   "conn_default",
			sdomain.KeyWorkOSDefaultOrganizationID + ":" + tenantID.String(): "org_default",
		}})
		s.redis = redis.NewClient(&redis.Options{Addr: redisStub.addr(), Protocol: 2})

		startURL, err := s.startWorkOS(context.Background(), domain.SSOStartInput{Provider: "workos", TenantID: tenantID, RedirectURL: "https://app.example/return"})
		if err != nil {
			t.Fatalf("startWorkOS unexpected err=%v", err)
		}
		u, err := url.Parse(startURL)
		if err != nil {
			t.Fatalf("parse start URL: %v", err)
		}
		state := u.Query().Get("state")
		if state == "" {
			t.Fatal("expected state in startWorkOS URL")
		}

		toks, err := s.callbackWorkOS(context.Background(), domain.SSOCallbackInput{Provider: "workos", Query: map[string][]string{"state": {state}, "code": {"c1"}}, UserAgent: "ua", IP: "127.0.0.1"})
		if err != nil {
			t.Fatalf("callbackWorkOS unexpected err=%v", err)
		}
		if toks.AccessToken == "" || toks.RefreshToken == "" {
			t.Fatalf("expected callbackWorkOS tokens, got %+v", toks)
		}

		link, err := s.OrganizationPortalLinkGeneratorWorkOS(context.Background(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: "workos", TenantID: tenantID, OrganizationID: "org_1", Intent: "user_management"})
		if err != nil {
			t.Fatalf("OrganizationPortalLinkGeneratorWorkOS unexpected err=%v", err)
		}
		if link.Link == "" {
			t.Fatal("expected non-empty portal link")
		}
	})
}
