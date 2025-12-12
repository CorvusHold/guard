package main

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echolog "github.com/labstack/gommon/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	"github.com/corvusHold/guard/internal/config"
	"github.com/corvusHold/guard/internal/logger"
	httpmetrics "github.com/corvusHold/guard/internal/metrics"
	"github.com/corvusHold/guard/internal/platform/validation"

	// Tenants DDD slice (factory)
	tenants "github.com/corvusHold/guard/internal/tenants"
	// Auth DDD slice (factory)
	pprof "net/http/pprof"

	_ "github.com/corvusHold/guard/docs" // side-effect import of generated docs
	auth "github.com/corvusHold/guard/internal/auth"
	settings "github.com/corvusHold/guard/internal/settings"
	settdomain "github.com/corvusHold/guard/internal/settings/domain"
	settrepo "github.com/corvusHold/guard/internal/settings/repository"
	settsvc "github.com/corvusHold/guard/internal/settings/service"
	"github.com/google/uuid"
	echoSwagger "github.com/swaggo/echo-swagger"
)

// @title           Guard CAS API
// @version         1.0
// @description     Central Authentication Service for multi-tenant identity management.
// @BasePath        /api
// @schemes         http
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization

// dynamicTenantCORS configures CORS per request by checking:
// 1) global env CORS_ALLOWED_ORIGINS
// 2) per-tenant app.cors_allowed_origins (if tenant context is present)
func dynamicTenantCORS(cfg config.Config, s settdomain.Service) echo.MiddlewareFunc {
	// normalize global origins
	glob := make([]string, 0, len(cfg.CORSAllowedOrigins))
	allowAny := false
	for _, o := range cfg.CORSAllowedOrigins {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if o == "*" {
			allowAny = true
		}
		glob = append(glob, o)
	}

	allowMethods := strings.Join([]string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodOptions,
	}, ", ")
	allowHeaders := strings.Join([]string{
		echo.HeaderOrigin,
		echo.HeaderContentType,
		echo.HeaderAccept,
		echo.HeaderAuthorization,
		"X-Guard-Client",
		"X-Tenant-ID",
		"X-Auth-Mode",
		"X-Portal-Token",
	}, ", ")

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			origin := req.Header.Get(echo.HeaderOrigin)
			if origin == "" {
				return next(c)
			}

			// Helper to set CORS headers for a specific allowed origin
			setHeaders := func() {
				res := c.Response().Header()
				res.Set(echo.HeaderVary, strings.Join([]string{echo.HeaderOrigin, echo.HeaderAccessControlRequestMethod, echo.HeaderAccessControlRequestHeaders}, ", "))
				res.Set(echo.HeaderAccessControlAllowOrigin, origin)
				res.Set(echo.HeaderAccessControlAllowMethods, allowMethods)
				res.Set(echo.HeaderAccessControlAllowHeaders, allowHeaders)
				res.Set(echo.HeaderAccessControlAllowCredentials, "true")
			}

			// 1) Allow any/global match first
			allowed := allowAny
			if !allowed {
				allowed = matchCORSOrigin(origin, glob)
			}

			// 2) If not globally allowed, attempt per-tenant lookup
			if !allowed {
				if tid := resolveTenantID(c); tid != nil {
					if val, err := s.GetString(c.Request().Context(), settdomain.KeyAppCORSAllowedOrigins, tid, ""); err == nil && val != "" {
						if matchCORSOrigin(origin, strings.Split(val, ",")) {
							allowed = true
						}
					}
				}
			}

			if allowed {
				setHeaders()
				if req.Method == http.MethodOptions {
					return c.NoContent(http.StatusNoContent)
				}
			}
			return next(c)
		}
	}
}

func matchCORSOrigin(origin string, patterns []string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return false
	}

	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "*" {
			return true
		}
		if origin == p {
			return true
		}
		if matchesWildcardOrigin(origin, p) {
			return true
		}
	}

	return false
}

func matchesWildcardOrigin(origin, pattern string) bool {
	pu, err := url.Parse(pattern)
	if err != nil {
		return false
	}
	ou, err := url.Parse(origin)
	if err != nil {
		return false
	}

	if pu.Scheme == "" || ou.Scheme == "" || !strings.EqualFold(pu.Scheme, ou.Scheme) {
		return false
	}

	phost := pu.Hostname()
	if !strings.HasPrefix(phost, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(phost, "*.")
	if suffix == "" {
		return false
	}

	host := ou.Hostname()
	if host == "" {
		return false
	}
	host = strings.ToLower(host)
	suffix = strings.ToLower(suffix)

	return strings.HasSuffix(host, "."+suffix)
}

// resolveTenantID tries to find a tenant UUID from query or route params.
func resolveTenantID(c echo.Context) *uuid.UUID {
	// Common: ?tenant_id=
	if v := strings.TrimSpace(c.QueryParam("tenant_id")); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			return &id
		}
	}
	// Route param patterns used in this API
	// e.g. /api/v1/tenants/:id/settings
	if strings.HasPrefix(c.Path(), "/api/v1/tenants/") {
		if v := strings.TrimSpace(c.Param("id")); v != "" {
			if id, err := uuid.Parse(v); err == nil {
				return &id
			}
		}
		if v := strings.TrimSpace(c.Param("tenant_id")); v != "" {
			if id, err := uuid.Parse(v); err == nil {
				return &id
			}
		}
	}
	// admin RBAC endpoints typically use tenant_id in query; nothing else to do
	return nil
}

func main() {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	log := logger.New(cfg.AppEnv)

	if handleCLICommand(os.Args[1:]) {
		return
	}

	// Init Postgres
	pgCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid DATABASE_URL")
	}
	pgPool, err := pgxpool.NewWithConfig(context.Background(), pgCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create pg pool")
	}
	defer pgPool.Close()

	// Init Redis/Valkey
	redisClient := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr,
		DB:   cfg.RedisDB,
	})
	defer func() {
		if cerr := redisClient.Close(); cerr != nil {
			log.Error().Err(cerr).Msg("redis close error")
		}
	}()

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// Enable verbose Echo logs in debug/test to surface ratelimit allow/block lines
	if os.Getenv("RATELIMIT_DEBUG") != "" {
		e.Logger.SetLevel(echolog.DEBUG)
	}

	// Prefer Cloudflare's header; then XFF; then X-Real-IP; then RemoteAddr.
	// Guard this behind TRUST_PROXY env to avoid trusting spoofable headers when not behind a proxy/CDN.
	if v := strings.ToLower(os.Getenv("TRUST_PROXY")); v == "true" || v == "1" || v == "yes" {
		// Parse optional TRUST_PROXY_CIDRS to restrict which proxy IPs are trusted
		var trustProxyCIDRs []*net.IPNet
		if cidrs := os.Getenv("TRUST_PROXY_CIDRS"); cidrs != "" {
			for _, part := range strings.Split(cidrs, ",") {
				s := strings.TrimSpace(part)
				if s == "" {
					continue
				}
				if _, n, err := net.ParseCIDR(s); err == nil {
					trustProxyCIDRs = append(trustProxyCIDRs, n)
				}
			}
		}
		e.IPExtractor = func(r *http.Request) string {
			// If CIDRs configured, only trust headers when RemoteAddr is in one of them
			remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
			if remoteHost == "" {
				remoteHost = r.RemoteAddr
			}
			if len(trustProxyCIDRs) > 0 {
				ip := net.ParseIP(remoteHost)
				allowed := false
				if ip != nil {
					for _, n := range trustProxyCIDRs {
						if n.Contains(ip) {
							allowed = true
							break
						}
					}
				}
				if !allowed {
					// Do not trust headers, return remote address
					return remoteHost
				}
			}
			if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
				return ip
			}
			if xff := r.Header.Get(echo.HeaderXForwardedFor); xff != "" {
				if i := strings.IndexByte(xff, ','); i >= 0 {
					return strings.TrimSpace(xff[:i])
				}
				return strings.TrimSpace(xff)
			}
			if ip := r.Header.Get(echo.HeaderXRealIP); ip != "" {
				return ip
			}
			if remoteHost != "" {
				return remoteHost
			}
			return r.RemoteAddr
		}
	}

	// Instantiate Settings service for dynamic CORS decisions
	settRepo := settrepo.New(pgPool)
	settService := settsvc.New(settRepo)

	// Middlewares
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.Logger())
	e.Use(httpmetrics.HTTPMiddleware())
	e.Use(middleware.Secure())
	// Dynamic, per-tenant CORS (augments global env allowlist)
	e.Use(dynamicTenantCORS(cfg, settService))

	// Validator
	e.Validator = validation.New()

	// Create versioned API groups
	api := e.Group("/api")
	apiV1 := api.Group("/v1")

	// Register domain routes via factories
	// Settings (tenant-scoped settings management)
	settings.RegisterV1(apiV1, pgPool, cfg)
	// Tenants and Auth
	tenants.RegisterV1(apiV1, pgPool)
	auth.RegisterV1(apiV1, pgPool, cfg)

	// Background dependency ping metrics
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			// DB ping
			{
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				start := time.Now()
				err := pgPool.Ping(ctx)
				dur := time.Since(start).Seconds()
				httpmetrics.ObserveDBPing(dur)
				httpmetrics.SetDBUp(err == nil)
				cancel()
			}
			// Redis ping
			{
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				start := time.Now()
				_, err := redisClient.Ping(ctx).Result()
				dur := time.Since(start).Seconds()
				httpmetrics.ObserveRedisPing(dur)
				httpmetrics.SetRedisUp(err == nil)
				cancel()
			}
		}
	}()

	// Health endpoint pings DB and Redis
	e.GET("/healthz", func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), 500*time.Millisecond)
		defer cancel()

		dbStatus := "ok"
		if err := pgPool.Ping(ctx); err != nil {
			dbStatus = "down"
		}

		cacheStatus := "ok"
		if _, err := redisClient.Ping(ctx).Result(); err != nil {
			cacheStatus = "down"
		}

		return c.JSON(http.StatusOK, map[string]any{
			"status": "ok",
			"time":   time.Now().UTC().Format(time.RFC3339),
			"db":     dbStatus,
			"cache":  cacheStatus,
		})
	})

	// Liveness: process is up
	e.GET("/livez", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	// Readiness: dependencies available (DB + Redis)
	e.GET("/readyz", func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), 500*time.Millisecond)
		defer cancel()

		if err := pgPool.Ping(ctx); err != nil {
			log.Error().Err(err).Msg("readyz: postgres ping failed")
			return c.NoContent(http.StatusServiceUnavailable)
		}
		if _, err := redisClient.Ping(ctx).Result(); err != nil {
			log.Error().Err(err).Msg("readyz: redis ping failed")
			return c.NoContent(http.StatusServiceUnavailable)
		}
		return c.NoContent(http.StatusOK)
	})

	// Prometheus metrics endpoint (optional CIDR ACL)
	var metricsAllowCIDRs []*net.IPNet
	if cidrs := os.Getenv("METRICS_ALLOW_CIDRS"); cidrs != "" {
		for _, part := range strings.Split(cidrs, ",") {
			s := strings.TrimSpace(part)
			if s == "" {
				continue
			}
			if _, n, err := net.ParseCIDR(s); err == nil {
				metricsAllowCIDRs = append(metricsAllowCIDRs, n)
			}
		}
	}

	metricsGroup := e.Group("")
	if len(metricsAllowCIDRs) > 0 {
		metricsGroup.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				clientIP := net.ParseIP(c.RealIP())
				allowed := false
				if clientIP != nil {
					for _, n := range metricsAllowCIDRs {
						if n.Contains(clientIP) {
							allowed = true
							break
						}
					}
				}
				if !allowed {
					return c.NoContent(http.StatusForbidden)
				}
				return next(c)
			}
		})
	}
	metricsGroup.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	// pprof endpoints (non-production only)
	if env := strings.ToLower(cfg.AppEnv); env != "prod" && env != "production" {
		grp := e.Group("/debug/pprof")
		grp.GET("/", echo.WrapHandler(http.HandlerFunc(pprof.Index)))
		grp.GET("/cmdline", echo.WrapHandler(http.HandlerFunc(pprof.Cmdline)))
		grp.GET("/profile", echo.WrapHandler(http.HandlerFunc(pprof.Profile)))
		grp.GET("/symbol", echo.WrapHandler(http.HandlerFunc(pprof.Symbol)))
		grp.GET("/trace", echo.WrapHandler(http.HandlerFunc(pprof.Trace)))
		// Named profiles
		grp.GET("/allocs", echo.WrapHandler(pprof.Handler("allocs")))
		grp.GET("/block", echo.WrapHandler(pprof.Handler("block")))
		grp.GET("/goroutine", echo.WrapHandler(pprof.Handler("goroutine")))
		grp.GET("/heap", echo.WrapHandler(pprof.Handler("heap")))
		grp.GET("/mutex", echo.WrapHandler(pprof.Handler("mutex")))
		grp.GET("/threadcreate", echo.WrapHandler(pprof.Handler("threadcreate")))
	}

	e.GET("/swagger/*", echoSwagger.WrapHandler)

	// Start server
	log.Info().Str("addr", cfg.AppAddr).Msg("starting api server")
	go func() {
		if err := e.Start(cfg.AppAddr); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("shutdown error")
	}
	log.Info().Msg("server stopped")
}
