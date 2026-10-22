# LoginApp

![CI](https://github.com/LuizPassos97/LoginApp/actions/workflows/ci.yml/badge.svg)
![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)
![Coverage](https://img.shields.io/badge/coverage-97.87%25%20lines%20%7C%2087.76%25%20branches-brightgreen)

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

Current measured coverage: **97.87% line coverage** and **87.76% branch coverage**.
The CI enforces a minimum of 85% for both lines and branches.

The integration and unit tests use an isolated SQLite database per test factory and cover:

- register, login, authenticated `/me`, refresh rotation, and logout
- concurrent refresh-token replay: only one exchange succeeds, then reuse invalidates its family (fail-closed)
- refresh tokens are persisted as hashes, not plain text
- refresh-token family isolation across logins/users, descendant revocation on replay, and additive migration
- logout with null, nonexistent, already revoked, and another user's refresh tokens
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
Each login starts a separate refresh-token family; rotation preserves that family.
Reusing any revoked member invalidates all still-active refresh tokens in that
family, including descendants of later rotations, without affecting other logins
or users. A revoked member remains replay evidence even after its expiry.

**Concurrency policy (fail-closed):** two exchanges using the same token produce
one `200` and one `401`. The second exchange is treated as reuse and invalidates
the family, including the refresh token returned by the successful exchange.
Clients must serialize refresh requests; there is no retry grace window. A new
login is required after this race. Rotation, descendant insertion, and replay
revocation use SQLite write transactions to prevent a surviving descendant.

**Access-token limitation:** family revocation does **not** revoke already issued
access JWTs. They remain valid until their 15-minute expiry, unless their specific
JTI is explicitly blocklisted by logout. The API does not track access JWTs by
family; the successful concurrent exchange's access JWT therefore remains valid.

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
Only the supplied refresh token belonging to the authenticated user is revoked;
logout does not revoke the entire family or other access JWTs. A null, nonexistent,
already revoked, or another user's refresh token still returns `204` and blocks
the caller's access JWT, without revoking another user's refresh token.

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
| Refresh token rotation | Conditional `UPDATE ... RETURNING`, preserved login family, atomic descendant revocation on replay (fail-closed) |
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
- The additive `family_id` migration runs after the existing schema migration,
  backfills a distinct family per historical row, and preserves current hashed
  tokens and their expiry/revocation state. It is idempotent. Historical lineage
  cannot be recovered: pre-upgrade ancestors cannot invalidate descendants that
  were already created before the upgrade. Rotation after upgrade retains the
  backfilled family. Stop old application instances before upgrading; mixed
  versions writing tokens without family IDs are not supported.
- Rate limiting is IP-based. Behind a reverse proxy, configure forwarded headers
  and consider adding account-based throttling.
