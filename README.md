# LoginApp

![CI](https://github.com/LuizPassos97/LoginApp/actions/workflows/ci.yml/badge.svg)
![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)
![Coverage](https://img.shields.io/badge/coverage-97.65%25%20lines%20%7C%2087.64%25%20branches-brightgreen)

A minimal, secure login system built with .NET 10 Minimal APIs, SQLite, and JWT.
It intentionally avoids ASP.NET Identity so the auth flow, storage model, and
security trade-offs are visible in the code.

## Why this project exists

This project demonstrates a security-conscious authentication flow implemented
without ASP.NET Identity, focusing on explicit token lifecycle, refresh-token
rotation, testability, and operational trade-offs.

## Stack

- **Runtime**: .NET 10 Minimal APIs
- **Database**: SQLite via `Microsoft.Data.Sqlite` (raw SQL, no ORM)
- **Auth**: JWT via `System.IdentityModel.Tokens.Jwt` + `Microsoft.AspNetCore.Authentication.JwtBearer`
- **Password hashing**: PBKDF2 (`Rfc2898DeriveBytes`, SHA-256, 100 000 iterations, 32-byte salt + hash)
- **Tests**: xUnit integration tests via `Microsoft.AspNetCore.Mvc.Testing`
- **CI**: GitHub Actions workflow for restore, build, and test

## Architecture

- `Program.cs`: Minimal API endpoints, middleware, auth, rate limiting, and startup wiring
- `Services/AuthService.cs`: registration, login, JWT generation, refresh-token hashing, rotation, and revocation
- `Services/TokenBlocklist.cs`: in-memory access-token revocation by JWT `jti`
- `Services/JwtSecretValidator.cs`: startup validation for unsafe JWT secrets
- `Data/Database.cs`: SQLite connection handling, schema creation, foreign keys, and legacy token migration
- `LoginApp.Tests/`: integration and security-focused tests with coverage enforcement

## How to run

```bash
dotnet run --project LoginApp.csproj
```

The server starts on `http://localhost:5000`.  
The SQLite database (`loginapp.db`) is created automatically on first run.

The checked-in JWT secret is development-only. Production startup fails if the
secret still looks like a dev value; override it with an environment variable,
user secret, or managed secret store:

```bash
Jwt__Secret="replace-with-a-cryptographically-random-secret" dotnet run --project LoginApp.csproj
```

## Tests

```bash
dotnet test LoginApp.slnx
```

Coverage can be collected locally with:

```bash
dotnet test LoginApp.slnx --configuration Release --collect:"XPlat Code Coverage"
```

Current measured coverage: **97.65% line coverage** and **87.64% branch coverage**.
The CI enforces a minimum of 85% for both lines and branches.

The integration and unit tests use an isolated SQLite database per test factory and cover:

- register, login, authenticated `/me`, refresh rotation, and logout
- concurrent refresh-token replay, where only one request can consume the token
- refresh tokens are persisted as hashes, not plain text
- refresh-token replay rejection
- expired access token rejection
- auth endpoint rate limiting
- same `401` behavior for unknown email vs wrong password
- invalid email and short password validation
- required payload validation and duplicate registration
- legacy refresh-token schema migration
- JWT secret validation and token blocklist expiry behavior

---

## Endpoints

### `POST /register`

```bash
curl -s -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"s3cr3tpass"}'
```

**201** `{ "message": "Account created." }`  
**409** `{ "error": "Email already registered." }`

---

### `POST /login`

```bash
curl -s -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"s3cr3tpass"}'
```

**200**
```json
{
  "accessToken": "<jwt — expires in 15 min>",
  "refreshToken": "<opaque token — expires in 30 days>"
}
```

**401** — same response for unknown email or wrong password (no enumeration)

---

### `POST /refresh`

Exchange a valid refresh token for a new access + refresh token pair.  
The old refresh token is consumed atomically and revoked immediately.

```bash
curl -s -X POST http://localhost:5000/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh_token>"}'
```

**200** `{ "accessToken": "...", "refreshToken": "..." }`  
**401** — token expired, already used, or revoked

---

### `POST /logout`

Blocklists the current access token and revokes the refresh token.  
Both are immediately invalid — no waiting for expiry.

```bash
curl -s -X POST http://localhost:5000/logout \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh_token>"}'
```

**204** No Content

---

### `GET /me`

Returns the authenticated user's profile.

```bash
curl -s http://localhost:5000/me \
  -H "Authorization: Bearer <access_token>"
```

**200**
```json
{
  "id": 1,
  "email": "alice@example.com",
  "createdAt": "2024-01-15T10:30:00"
}
```

**401** — missing, invalid, expired, or revoked token

---

## Full curl walkthrough

```bash
# 1. Register
curl -s -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"s3cr3tpass"}'

# 2. Login — capture both tokens
RESPONSE=$(curl -s -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"s3cr3tpass"}')

ACCESS=$(echo $RESPONSE | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)
REFRESH=$(echo $RESPONSE | grep -o '"refreshToken":"[^"]*"' | cut -d'"' -f4)

# 3. Access protected route
curl -s http://localhost:5000/me -H "Authorization: Bearer $ACCESS"

# 4. Refresh (rotate tokens)
NEW=$(curl -s -X POST http://localhost:5000/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}")

NEW_ACCESS=$(echo $NEW | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)
NEW_REFRESH=$(echo $NEW | grep -o '"refreshToken":"[^"]*"' | cut -d'"' -f4)

# 5. Logout — invalidates both tokens immediately
curl -s -X POST http://localhost:5000/logout \
  -H "Authorization: Bearer $NEW_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$NEW_REFRESH\"}"

# 6. Verify access token is dead
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/me \
  -H "Authorization: Bearer $NEW_ACCESS"
# → 401
```

---

## Security design

| Concern | Implementation |
|---|---|
| Password storage | PBKDF2-SHA256, 100 000 iterations, 32-byte random salt per user |
| Timing-safe compare | `CryptographicOperations.FixedTimeEquals` |
| User enumeration | Login always runs full PBKDF2 before returning 401, same response for unknown email vs wrong password |
| SQL injection | Parameterized queries everywhere, zero string interpolation |
| JWT validation | Issuer, audience, lifetime, signature — `ClockSkew = Zero` |
| Token revocation | Access token JTI blocklisted on logout; refresh token revoked in DB |
| Refresh token storage | Opaque refresh tokens are HMAC-SHA256 hashed before persistence |
| Refresh token rotation | Old token is consumed via conditional `UPDATE ... RETURNING`; replayed tokens are rejected |
| Brute force | Rate limiter: 10 requests/min per IP on all auth endpoints (sliding window, 429 on breach) |
| Refresh token format | 64-byte CSPRNG, URL-safe base64, returned once to the client |
| SQLite integrity | Foreign keys are enabled per connection |
| Config safety | Startup rejects weak/default JWT secrets and production dev secrets |

## Design trade-offs

- The access-token blocklist is in-memory. That is fine for this small single-node
  app, but a real multi-instance deployment should use Redis or another shared
  store.
- SQLite keeps the project easy to run locally. For production, the same
  repository/service boundaries can move to PostgreSQL or SQL Server.
- Refresh-token migration invalidates legacy plain-text refresh tokens if an old
  database is detected. Users must log in again, which is safer than preserving
  reusable secrets.
- Rate limiting is IP-based. Behind a reverse proxy, configure forwarded headers
  and consider adding account-based throttling.
