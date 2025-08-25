package main

import (
	"context"
	"net"
	"net/http"
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
	_ "github.com/corvusHold/guard/docs" // side-effect import of generated docs
	auth "github.com/corvusHold/guard/internal/auth"
	settings "github.com/corvusHold/guard/internal/settings"
	echoSwagger "github.com/swaggo/echo-swagger"
	pprof "net/http/pprof"
)

// @title           Guard CAS API
// @version         1.0
// @description     Central Authentication Service for multi-tenant identity management.
// @BasePath        /
// @schemes         http
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization

func main() {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	log := logger.New(cfg.AppEnv)
	log.Info().Str("addr", cfg.AppAddr).Msg("starting api server")

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

	// Middlewares
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.Logger())
	e.Use(httpmetrics.HTTPMiddleware())
	e.Use(middleware.Secure())
	// Configurable body size limit (default 2M)
	e.Use(middleware.BodyLimit(cfg.BodyLimit))
	// Apply handler-level timeout, skipping health/metrics endpoints
	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: cfg.HandlerTimeout,
		Skipper: func(c echo.Context) bool {
			p := c.Path()
			return p == "/livez" || p == "/readyz" || p == "/healthz" || p == "/metrics" || strings.HasPrefix(p, "/debug/pprof")
		},
	}))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: cfg.CORSAllowedOrigins,
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	// Validator
	e.Validator = validation.New()

	// Register domain routes via factories
	// Settings (tenant-scoped settings management)
	settings.Register(e, pgPool, cfg)
	// Tenants and Auth
	tenants.Register(e, pgPool)
	auth.Register(e, pgPool, cfg)

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
			return c.NoContent(http.StatusServiceUnavailable)
		}
		if _, err := redisClient.Ping(ctx).Result(); err != nil {
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
	go func() {
		// Production safety checks
		if env := strings.ToLower(cfg.AppEnv); env == "prod" || env == "production" {
			if cfg.JWTSigningKey == "" || cfg.JWTSigningKey == "dev-insecure-change-this" || len(cfg.JWTSigningKey) < 32 {
				log.Fatal().Msg("insecure JWT_SIGNING_KEY for production; set a strong secret (>=32 bytes)")
			}
		}

		srv := &http.Server{
			Addr:              cfg.AppAddr,
			ReadTimeout:       10 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20, // 1 MiB
		}
		if err := e.StartServer(srv); err != nil && err != http.ErrServerClosed {
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
