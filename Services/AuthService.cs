using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using LoginApp.Data;
using LoginApp.Models;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;

namespace LoginApp.Services;

public class AuthService
{
    private readonly Database _db;
    private readonly string _jwtSecret;
    private readonly string _jwtIssuer;
    private readonly string _jwtAudience;
    private readonly byte[] _refreshTokenHashKey;

    private static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(30);

    public AuthService(IConfiguration config, Database db)
    {
        _db = db;
        _jwtSecret = config["Jwt:Secret"] ?? throw new InvalidOperationException("Jwt:Secret is not configured.");
        _jwtIssuer = config["Jwt:Issuer"] ?? "LoginApp";
        _jwtAudience = config["Jwt:Audience"] ?? "LoginApp";
        _refreshTokenHashKey = Encoding.UTF8.GetBytes(config["RefreshTokens:HashKey"] ?? _jwtSecret);
    }

    public async Task<(bool success, string error)> RegisterAsync(string email, string password)
    {
        var (hash, salt) = HashPassword(password);

        await using var conn = await _db.OpenConnectionAsync();

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO users (email, password_hash, password_salt)
            VALUES (@email, @hash, @salt);
            """;
        cmd.Parameters.AddWithValue("@email", email);
        cmd.Parameters.AddWithValue("@hash", hash);
        cmd.Parameters.AddWithValue("@salt", salt);

        try
        {
            await cmd.ExecuteNonQueryAsync();
            return (true, string.Empty);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // SQLITE_CONSTRAINT (UNIQUE)
        {
            return (false, "Email already registered.");
        }
    }

    public async Task<(bool success, string accessToken, string refreshToken, string error)> LoginAsync(
        string email, string password)
    {
        var user = await FindUserByEmailAsync(email);

        // Always run PBKDF2 to prevent timing-based user enumeration.
        // When the user doesn't exist, verify against a dummy hash so execution
        // time is indistinguishable from a real failed attempt.
        var hashToVerify = user?.PasswordHash ?? Convert.ToBase64String(new byte[32]);
        var saltToVerify = user?.PasswordSalt ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var passwordValid = VerifyPassword(password, hashToVerify, saltToVerify);

        if (user is null || !passwordValid)
            return (false, string.Empty, string.Empty, "Invalid credentials.");

        var accessToken = GenerateAccessToken(user);
        var refreshToken = await CreateRefreshTokenAsync(user.Id);
        return (true, accessToken, refreshToken, string.Empty);
    }

    public async Task<(bool success, string accessToken, string refreshToken)> RefreshAsync(string token)
    {
        var now = DateTimeOffset.UtcNow;
        var tokenHash = HashRefreshToken(token);

        await using var conn = await _db.OpenConnectionAsync();
        await using var tx = await conn.BeginTransactionAsync();

        await using var revoke = conn.CreateCommand();
        revoke.Transaction = (SqliteTransaction)tx;
        revoke.CommandText = """
            UPDATE refresh_tokens
               SET revoked_at = @revokedAt
             WHERE token_hash = @tokenHash
               AND revoked_at IS NULL
               AND expires_at > @now
            RETURNING user_id;
            """;
        revoke.Parameters.AddWithValue("@revokedAt", now.ToString("o"));
        revoke.Parameters.AddWithValue("@tokenHash", tokenHash);
        revoke.Parameters.AddWithValue("@now", now.ToString("o"));

        var userIdResult = await revoke.ExecuteScalarAsync();
        if (userIdResult is null)
        {
            await tx.RollbackAsync();
            return (false, string.Empty, string.Empty);
        }

        var user = await FindUserByIdAsync(Convert.ToInt32(userIdResult), conn, (SqliteTransaction)tx);
        if (user is null)
        {
            await tx.RollbackAsync();
            return (false, string.Empty, string.Empty);
        }

        var newAccessToken = GenerateAccessToken(user);
        var newRefreshToken = await CreateRefreshTokenAsync(user.Id, conn, (SqliteTransaction)tx);
        await tx.CommitAsync();

        return (true, newAccessToken, newRefreshToken);
    }

    public async Task RevokeRefreshTokenAsync(string token, int userId)
    {
        await using var conn = await _db.OpenConnectionAsync();

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE refresh_tokens
               SET revoked_at = @revokedAt
             WHERE token_hash = @tokenHash AND user_id = @userId AND revoked_at IS NULL;
            """;
        cmd.Parameters.AddWithValue("@revokedAt", DateTimeOffset.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("@tokenHash", HashRefreshToken(token));
        cmd.Parameters.AddWithValue("@userId", userId);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<User?> FindUserByIdAsync(int id)
    {
        await using var conn = await _db.OpenConnectionAsync();

        return await FindUserByIdAsync(id, conn, null);
    }

    private static async Task<User?> FindUserByIdAsync(int id, SqliteConnection conn, SqliteTransaction? tx)
    {

        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT id, email, created_at FROM users WHERE id = @id;";
        cmd.Parameters.AddWithValue("@id", id);

        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;

        return new User
        {
            Id = reader.GetInt32(0),
            Email = reader.GetString(1),
            CreatedAt = DateTime.Parse(reader.GetString(2))
        };
    }

    private async Task<User?> FindUserByEmailAsync(string email)
    {
        await using var conn = await _db.OpenConnectionAsync();

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, email, password_hash, password_salt
              FROM users
             WHERE email = @email;
            """;
        cmd.Parameters.AddWithValue("@email", email);

        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;

        return new User
        {
            Id = reader.GetInt32(0),
            Email = reader.GetString(1),
            PasswordHash = reader.GetString(2),
            PasswordSalt = reader.GetString(3)
        };
    }

    private async Task<string> CreateRefreshTokenAsync(int userId)
    {
        await using var conn = await _db.OpenConnectionAsync();
        return await CreateRefreshTokenAsync(userId, conn, null);
    }

    private async Task<string> CreateRefreshTokenAsync(
        int userId,
        SqliteConnection conn,
        SqliteTransaction? tx)
    {
        var token = GenerateOpaqueToken();
        var tokenHash = HashRefreshToken(token);
        var expiresAt = DateTimeOffset.UtcNow.Add(RefreshTokenLifetime);

        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (@userId, @tokenHash, @expiresAt);
            """;
        cmd.Parameters.AddWithValue("@userId", userId);
        cmd.Parameters.AddWithValue("@tokenHash", tokenHash);
        cmd.Parameters.AddWithValue("@expiresAt", expiresAt.ToString("o"));
        await cmd.ExecuteNonQueryAsync();

        return token;
    }

    private static (string hash, string salt) HashPassword(string password)
    {
        var saltBytes = RandomNumberGenerator.GetBytes(32);
        var hashBytes = Rfc2898DeriveBytes.Pbkdf2(
            password, saltBytes, 100_000, HashAlgorithmName.SHA256, outputLength: 32);
        return (Convert.ToBase64String(hashBytes), Convert.ToBase64String(saltBytes));
    }

    private static bool VerifyPassword(string password, string storedHash, string storedSalt)
    {
        try
        {
            var saltBytes = Convert.FromBase64String(storedSalt);
            var hashBytes = Rfc2898DeriveBytes.Pbkdf2(
                password, saltBytes, 100_000, HashAlgorithmName.SHA256, outputLength: 32);
            return CryptographicOperations.FixedTimeEquals(hashBytes, Convert.FromBase64String(storedHash));
        }
        catch
        {
            return false;
        }
    }

    private string HashRefreshToken(string token)
    {
        using var hmac = new HMACSHA256(_refreshTokenHashKey);
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(token)));
    }

    private static string GenerateOpaqueToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private string GenerateAccessToken(User user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now = DateTimeOffset.UtcNow;

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };

        var token = new JwtSecurityToken(
            issuer: _jwtIssuer,
            audience: _jwtAudience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: now.Add(AccessTokenLifetime).UtcDateTime,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
