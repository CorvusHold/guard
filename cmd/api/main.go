package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/corvusHold/guard/internal/config"
	"github.com/corvusHold/guard/internal/logger"
	"github.com/corvusHold/guard/internal/platform/validation"

	// Tenants DDD slice (factory)
	tenants "github.com/corvusHold/guard/internal/tenants"
	// Auth DDD slice (factory)
	_ "github.com/corvusHold/guard/docs" // side-effect import of generated docs
	auth "github.com/corvusHold/guard/internal/auth"
	echoSwagger "github.com/swaggo/echo-swagger"
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
	defer redisClient.Close()

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// Middlewares
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.Logger())
	e.Use(middleware.Secure())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: cfg.CORSAllowedOrigins,
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	// Validator
	e.Validator = validation.New()

	// Register domain routes via factories
	tenants.Register(e, pgPool)
	auth.Register(e, pgPool, cfg)

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
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	// Start server
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
