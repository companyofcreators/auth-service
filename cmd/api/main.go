package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/companyofcreators/auth-service/internal/config"
	app "github.com/companyofcreators/auth-service/internal/application/auth"
	"github.com/companyofcreators/auth-service/internal/infrastructure/db"
	"github.com/companyofcreators/auth-service/internal/infrastructure/hasher"
	"github.com/companyofcreators/auth-service/internal/infrastructure/jwt"
	infrakafka "github.com/companyofcreators/auth-service/internal/infrastructure/kafka"
	infraredis "github.com/companyofcreators/auth-service/internal/infrastructure/redis"
	"github.com/companyofcreators/auth-service/internal/interfaces/http/handler"
	httprouter "github.com/companyofcreators/auth-service/internal/interfaces/http"
)

func main() {
	cfg := config.Load()
	if cfg == nil {
		slog.Error("failed to load config")
		os.Exit(1)
	}

	logLevel := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	logger.Info("starting auth service", "env", cfg.Env)

	pgDB, err := db.Connect(cfg.DBDSN)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pgDB.Close()
	logger.Info("connected to postgresql")

	if err := db.RunMigrations(pgDB); err != nil {
		logger.Warn("some migrations failed, continuing", "error", err)
	}

	redisClient, err := infraredis.Connect(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		logger.Error("failed to connect to redis", "error", err)
		os.Exit(1)
	}
	defer redisClient.Close()
	logger.Info("connected to redis")

	tokenService, err := jwt.NewTokenService(
		cfg.JWTPrivateKeyPath,
		cfg.JWTPublicKeyPath,
		cfg.AccessTokenTTL,
	)
	if err != nil {
		logger.Error("failed to create token service", "error", err)
		os.Exit(1)
	}

	bcryptHasher := hasher.NewBcryptHasher(cfg.BcryptCost)

	kafkaProducer := infrakafka.NewProducer(cfg.KafkaBrokers, logger)
	defer kafkaProducer.Close()

	credentialRepo := db.NewCredentialRepo(pgDB)
	refreshRepo := infraredis.NewRefreshTokenRepo(redisClient)
	verifyRepo := infraredis.NewVerifyTokenRepo(redisClient)

	registerUC := app.NewRegisterUseCase(
		credentialRepo,
		refreshRepo,
		verifyRepo,
		tokenService,
		bcryptHasher,
		kafkaProducer,
		logger,
		cfg.RefreshTokenTTL,
		cfg.VerifyTokenTTL,
		cfg.BcryptCost,
	)

	loginUC := app.NewLoginUseCase(
		credentialRepo,
		refreshRepo,
		tokenService,
		bcryptHasher,
		kafkaProducer,
		logger,
		cfg.RefreshTokenTTL,
		cfg.RequireEmailVerified,
	)

	refreshUC := app.NewRefreshUseCase(
		credentialRepo,
		refreshRepo,
		tokenService,
		logger,
		cfg.RefreshTokenTTL,
	)

	validateUC := app.NewValidateUseCase(tokenService)

	logoutUC := app.NewLogoutUseCase(
		refreshRepo,
		kafkaProducer,
		logger,
	)

	verifyEmailUC := app.NewVerifyEmailUseCase(
		credentialRepo,
		verifyRepo,
		logger,
	)

	authHandler := handler.NewAuthHandler(
		registerUC,
		loginUC,
		refreshUC,
		validateUC,
		logoutUC,
		verifyEmailUC,
		logger,
		int(cfg.AccessTokenTTL.Seconds()),
		int(cfg.RefreshTokenTTL.Seconds()),
		cfg.Env,
	)

	router := httprouter.NewRouter(authHandler)

	srv := &http.Server{
		Addr:         cfg.HTTPAddress,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("auth service started", "address", cfg.HTTPAddress)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down auth service")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("http server shutdown failed", "error", err)
	}

	logger.Info("auth service stopped")
}
