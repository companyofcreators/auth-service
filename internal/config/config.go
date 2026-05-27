package config

import (
	"log/slog"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	HTTPAddress       string        `env:"HTTP_ADDRESS" env-default:":8081"`
	DBDSN             string        `env:"DB_DSN" env-required:"true"`
	RedisAddr         string        `env:"REDIS_ADDR" env-default:"localhost:6379"`
	RedisPassword     string        `env:"REDIS_PASSWORD"`
	RedisDB           int           `env:"REDIS_DB" env-default:"0"`
	JWTPrivateKeyPath string        `env:"JWT_PRIVATE_KEY_PATH" env-required:"true"`
	JWTPublicKeyPath  string        `env:"JWT_PUBLIC_KEY_PATH"`
	AccessTokenTTL    time.Duration `env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL   time.Duration `env:"REFRESH_TOKEN_TTL" env-default:"720h"`
	VerifyTokenTTL    time.Duration `env:"VERIFY_TOKEN_TTL" env-default:"24h"`
	KafkaBrokers      []string      `env:"KAFKA_BROKERS" env-default:"localhost:9092"`
	Env               string        `env:"ENV" env-default:"local"`
	LogLevel          string        `env:"LOG_LEVEL" env-default:"info"`
	BcryptCost        int           `env:"BCRYPT_COST" env-default:"12"`
	RequireEmailVerified bool   `env:"REQUIRE_EMAIL_VERIFIED" env-default:"false"`
	FrontendURL           string `env:"FRONTEND_URL" env-default:"http://localhost:5173"`
	BaseURL               string `env:"BASE_URL" env-default:"http://localhost:8080"`
	HeaderHMACKey         string `env:"HEADER_HMAC_KEY" env-default:"diploma-internal-hmac-secret-key-2026"`
}

func Load() *Config {
	if err := godotenv.Load(".env"); err != nil {
		slog.Warn(".env file not found, using environment variables", "error", err)
	}

	var cfg Config
	if err := cleanenv.ReadConfig(".env", &cfg); err != nil {
		slog.Error("failed to read configuration", "error", err)
		return nil
	}

	if cfg.BcryptCost < 12 {
		slog.Warn("bcrypt cost below minimum, setting to 12")
		cfg.BcryptCost = 12
	}

	return &cfg
}
