Auth Service
auth-service/
├── cmd/
│   └── api/
│       └── main.go
├── internal/
│   ├── app/
│   │   └── container.go                # DI: репозитории, сервисы, хендлеры
│   ├── config/
│   │   └── config.go                   # PORT, DB_DSN, REDIS_URL, JWT_SECRET, ACCESS_TTL, REFRESH_TTL
│   ├── domain/
│   │   └── auth/
│   │       ├── entity.go               # Credential (ID, Email, PasswordHash, CreatedAt), RefreshToken (UserID, TokenHash, ExpiresAt)
│   │       ├── repository.go           # CredentialRepository, RefreshTokenRepository (интерфейсы)
│   │       ├── service.go              # TokenService (интерфейс: GeneratePair, ValidateAccess, ValidateRefresh)
│   │       └── errors.go
│   ├── application/
│   │   └── auth/
│   │       ├── register.go             # RegisterUseCase (создание credential + генерация токенов)
│   │       ├── login.go
│   │       ├── refresh.go
│   │       └── validate.go
│   ├── infrastructure/
│   │   ├── db/
│   │   │   ├── postgres.go
│   │   │   └── credential_repo.go      # реализация CredentialRepository (sqlx)
│   │   ├── redis/
│   │   │   ├── redis_client.go
│   │   │   └── refresh_token_repo.go   # реализация RefreshTokenRepository (храним в Redis: ключ "refresh:user_id" → хеш токена, TTL)
│   │   ├── jwt/
│   │   │   └── jwt_service.go          # реализация TokenService (JWT + вызов refresh repo)
│   │   └── hasher/
│   │       └── bcrypt_hasher.go
│   ├── interfaces/
│   │   └── http/
│   │       ├── handler/
│   │       │   └── auth_handler.go
│   │       ├── dto.go                  # RegisterRequest, LoginRequest, LoginResponse, ValidateRequest, ValidateResponse
│   │       └── router.go
│   └── pkg/
│       ├── logger
│       └── validator
├── migrations/                         # только таблица credentials (id, email, password_hash, created_at)
├── go.mod
├── Dockerfile
└── .env

User Service 

user-service/
├── cmd/api/main.go
├── internal/
│   ├── config/
│   ├── domain/
│   │   └── user/
│   │       ├── entity.go      # Profile (ID, FirstName, LastName, AvatarURL, ...)
│   │       ├── repository.go
│   │       └── service.go
│   ├── infrastructure/db/postgres.go + user_repo.go
│   ├── interfaces/http/
│   │   ├── handler/profile_handler.go   # GET /internal/users/{id} (читает X-User-Id из заголовка для авторизации)
│   │   ├── dto.go
│   │   └── router.go
│   └── pkg/...
├── migrations/               # таблица user_profiles
└── ...

Api Gateway
api-gateway/
├── cmd/main.go
├── internal/
│   ├── app/container.go                 # DI: клиенты к auth-service, user-service, order-service
│   ├── config/
│   ├── middleware/
│   │   └── auth.go                      # вызывает auth-service /validate
│   ├── proxy/
│   │   └── reverse_proxy.go
│   ├── aggregator/
│   │   ├── user_profile.go              # агрегирует из user-service (+ заказы)
│   │   └── ...
│   ├── transport/http/
│   │   ├── router.go
│   │   └── dto.go
│   └── pkg/
│       ├── logger
│       └── http_client
└── ...