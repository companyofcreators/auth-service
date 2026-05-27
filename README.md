# Auth Service

Сервис аутентификации. Управляет регистрацией, логином, JWT токенами.

## Обязанности

- Регистрация пользователей с ролями (user, master, moderator, admin)
- Логин с проверкой bcrypt паролей
- Выпуск JWT access токенов (RS256, 15 мин)
- Refresh token rotation (opaque tokens, 30 дней)
- Token theft detection
- Email verification flow
- Kafka события: user.created, auth.login, auth.logout, user.verification.created

## Эндпоинты

| Метод | Путь | Назначение | Auth |
|-------|------|-----------|------|
| `GET` | `/internal/health` | Health check | Нет |
| `POST` | `/api/v1/auth/register` | Регистрация | Нет |
| `POST` | `/api/v1/auth/login` | Логин | Нет |
| `POST` | `/api/v1/auth/refresh` | Обновление токенов | Cookie |
| `DELETE` | `/api/v1/auth/logout` | Выход | Cookie |
| `GET` | `/api/v1/auth/verify-email?token=` | Подтверждение email | Нет |

## Cookies

| Cookie | TTL | HttpOnly | Secure (prod) | SameSite |
|--------|-----|----------|---------------|----------|
| `access_token` | 15m | Да | Да | Lax |
| `refresh_token` | 30d | Да | Да | Lax |

## Конфигурация

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `HTTP_ADDRESS` | `:8081` | Адрес HTTP сервера |
| `DB_DSN` | — | PostgreSQL DSN |
| `REDIS_ADDR` | `localhost:6379` | Адрес Redis |
| `REDIS_PASSWORD` | — | Пароль Redis |
| `REDIS_DB` | `0` | Номер БД Redis |
| `JWT_PRIVATE_KEY_PATH` | — | Путь к RSA приватному ключу |
| `ACCESS_TOKEN_TTL` | `15m` | Время жизни access токена |
| `REFRESH_TOKEN_TTL` | `720h` | Время жизни refresh токена |
| `KAFKA_BROKERS` | `localhost:9092` | Kafka брокеры |
| `ENV` | `local` | Окружение |
| `LOG_LEVEL` | `info` | Уровень логирования |

## Безопасность

- Пароли: bcrypt cost 12
- JWT: RS256 с приватным ключом
- Refresh tokens: opaque random 64-byte hex, хранятся как SHA256 в Redis
- Token theft detection: при повторном использовании refresh — все токены юзера удаляются
- Rate limiting: 5 попыток логина/регистрации в минуту с одного IP

## Kafka Events

| Topic | Триггер | Данные |
|-------|---------|--------|
| `user.created` | Успешная регистрация | user_id, email, roles |
| `auth.login` | Успешный логин | user_id, email |
| `auth.logout` | Выход | user_id |
| `user.verification.created` | Нужна верификация email | user_id, email, verification_token |
