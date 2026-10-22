using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using LoginApp.Data;
using LoginApp.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.FileProviders;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace LoginApp.Tests;

public sealed class AuthFlowTests
{
    [Fact]
    public async Task UserCanRegisterLoginReadProfileRefreshAndLogout()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        var register = await client.PostAsJsonAsync("/register", new
        {
            email = "alice@example.com",
            password = "s3cr3tpass"
        });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var tokens = await LoginAsync(client, "alice@example.com", "s3cr3tpass");

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var me = await client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);

        var refreshedResponse = await client.PostAsJsonAsync("/refresh", new
        {
            refreshToken = tokens.RefreshToken
        });
        Assert.Equal(HttpStatusCode.OK, refreshedResponse.StatusCode);

        var refreshed = await refreshedResponse.Content.ReadFromJsonAsync<AuthTokens>();
        Assert.NotNull(refreshed);
        Assert.False(string.IsNullOrWhiteSpace(refreshed.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(refreshed.RefreshToken));
        Assert.NotEqual(tokens.RefreshToken, refreshed.RefreshToken);

        var replay = await client.PostAsJsonAsync("/refresh", new
        {
            refreshToken = tokens.RefreshToken
        });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshed.AccessToken);
        var logout = await client.PostAsJsonAsync("/logout", new
        {
            refreshToken = refreshed.RefreshToken
        });
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var afterLogout = await client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.Unauthorized, afterLogout.StatusCode);
    }

    [Fact]
    public async Task LogoutCannotRevokeAnotherUsersRefreshToken()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        await RegisterAsync(client, "alice@example.com", "s3cr3tpass");
        await RegisterAsync(client, "bob@example.com", "s3cr3tpass");
        var alice = await LoginAsync(client, "alice@example.com", "s3cr3tpass");
        var bob = await LoginAsync(client, "bob@example.com", "s3cr3tpass");

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", alice.AccessToken);
        var logout = await client.PostAsJsonAsync("/logout", new
        {
            refreshToken = bob.RefreshToken
        });
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var afterLogout = await client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.Unauthorized, afterLogout.StatusCode);

        client.DefaultRequestHeaders.Authorization = null;
        var refresh = await client.PostAsJsonAsync("/refresh", new
        {
            refreshToken = bob.RefreshToken
        });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("missing")]
    [InlineData("revoked")]
    public async Task LogoutWithNullMissingOrRevokedTokenBlocksOnlyCallingAccessToken(string? tokenState)
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();
        var auth = app.Services.GetRequiredService<AuthService>();
        await auth.RegisterAsync("alice@example.com", "s3cr3tpass");
        await auth.RegisterAsync("bob@example.com", "s3cr3tpass");
        var caller = await auth.LoginAsync("alice@example.com", "s3cr3tpass");
        var sibling = await auth.LoginAsync("alice@example.com", "s3cr3tpass");
        var stranger = await auth.LoginAsync("bob@example.com", "s3cr3tpass");
        string? refreshToken = tokenState;
        string? descendant = null;
        if (tokenState == "revoked")
        {
            var rotation = await auth.RefreshAsync(caller.refreshToken);
            Assert.True(rotation.success);
            descendant = rotation.refreshToken;
            refreshToken = caller.refreshToken;
        }
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", caller.accessToken);
        var logout = await client.PostAsJsonAsync("/logout", new { refreshToken });
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
        if (descendant is not null)
            Assert.True((await auth.RefreshAsync(descendant)).success);
        foreach (var other in new[] { sibling, stranger })
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", other.accessToken);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/me")).StatusCode);
            Assert.True((await auth.RefreshAsync(other.refreshToken)).success);
        }
    }

    [Fact]
    public async Task LogoutRevokesTheAuthenticatedUsersRefreshToken()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        await RegisterAsync(client, "owner@example.com", "s3cr3tpass");
        var tokens = await LoginAsync(client, "owner@example.com", "s3cr3tpass");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        var logout = await client.PostAsJsonAsync("/logout", new
        {
            refreshToken = tokens.RefreshToken
        });
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        client.DefaultRequestHeaders.Authorization = null;
        var refresh = await client.PostAsJsonAsync("/refresh", new
        {
            refreshToken = tokens.RefreshToken
        });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    [Fact]
    public async Task ConcurrentRefreshRequestsFailClosedAndInvalidateWinningRefreshToken()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        await RegisterAsync(client, "race@example.com", "s3cr3tpass");
        var tokens = await LoginAsync(client, "race@example.com", "s3cr3tpass");
        var otherSession = await LoginAsync(client, "race@example.com", "s3cr3tpass");

        using var ready = new CountdownEvent(2);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var refreshTasks = Enumerable.Range(0, 2)
            .Select(_ => Task.Run(async () =>
            {
                ready.Signal();
                await start.Task;
                return await client.PostAsJsonAsync("/refresh", new { refreshToken = tokens.RefreshToken });
            }))
            .ToArray();
        Assert.True(ready.Wait(TimeSpan.FromSeconds(10)));
        start.SetResult();

        var responses = await Task.WhenAll(refreshTasks);

        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.OK));
        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.Unauthorized));
        var winner = await responses.Single(response => response.StatusCode == HttpStatusCode.OK)
            .Content.ReadFromJsonAsync<AuthTokens>();
        Assert.NotNull(winner);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/refresh",
            new { refreshToken = winner.RefreshToken })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/refresh",
            new { refreshToken = otherSession.RefreshToken })).StatusCode);
    }

    [Fact]
    public async Task LoginCreatesIndependentFamiliesAndRotationPreservesFamily()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();
        await RegisterAsync(client, "families@example.com", "s3cr3tpass");
        var first = await LoginAsync(client, "families@example.com", "s3cr3tpass");
        await LoginAsync(client, "families@example.com", "s3cr3tpass");
        var refresh = await client.PostAsJsonAsync("/refresh", new { refreshToken = first.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        await using var conn = new SqliteConnection($"Data Source={app.DatabasePath}");
        await conn.OpenAsync();
        await using var query = conn.CreateCommand();
        query.CommandText = "SELECT family_id FROM refresh_tokens ORDER BY id;";
        await using var reader = await query.ExecuteReaderAsync();
        var families = new List<string>();
        while (await reader.ReadAsync()) families.Add(reader.GetString(0));
        Assert.Equal(3, families.Count);
        Assert.All(families, family => Assert.False(string.IsNullOrWhiteSpace(family)));
        Assert.NotEqual(families[0], families[1]);
        Assert.Equal(families[0], families[2]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReplayingAncestorRevokesDescendantsButNotOtherSessionsOrUsers(bool ancestorExpired)
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();
        var auth = app.Services.GetRequiredService<AuthService>();
        await auth.RegisterAsync("alice@example.com", "s3cr3tpass");
        await auth.RegisterAsync("bob@example.com", "s3cr3tpass");
        var root = await auth.LoginAsync("alice@example.com", "s3cr3tpass");
        var otherSession = await auth.LoginAsync("alice@example.com", "s3cr3tpass");
        var otherUser = await auth.LoginAsync("bob@example.com", "s3cr3tpass");
        var child = await auth.RefreshAsync(root.refreshToken);
        Assert.True(child.success);
        var grandchild = await auth.RefreshAsync(child.refreshToken);
        Assert.True(grandchild.success);
        if (ancestorExpired)
        {
            await using var conn = new SqliteConnection($"Data Source={app.DatabasePath}");
            await conn.OpenAsync();
            await using var expire = conn.CreateCommand();
            expire.CommandText = "UPDATE refresh_tokens SET expires_at = '2000-01-01' WHERE id = 1;";
            await expire.ExecuteNonQueryAsync();
        }

        Assert.False((await auth.RefreshAsync(root.refreshToken)).success);
        Assert.False((await auth.RefreshAsync(grandchild.refreshToken)).success);
        Assert.True((await auth.RefreshAsync(otherSession.refreshToken)).success);
        Assert.True((await auth.RefreshAsync(otherUser.refreshToken)).success);
        // Family revocation does not revoke already issued access JWTs.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", grandchild.accessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/me")).StatusCode);
    }

    [Fact]
    public async Task ExpiredUnrevokedRefreshTokenIsRejectedWithoutRevokingOtherSessions()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();
        var auth = app.Services.GetRequiredService<AuthService>();
        await auth.RegisterAsync("expired@example.com", "s3cr3tpass");
        var expired = await auth.LoginAsync("expired@example.com", "s3cr3tpass");
        var other = await auth.LoginAsync("expired@example.com", "s3cr3tpass");
        await using var connection = new SqliteConnection($"Data Source={app.DatabasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE refresh_tokens SET expires_at = '2000-01-01' WHERE id = 1;";
        await command.ExecuteNonQueryAsync();

        Assert.False((await auth.RefreshAsync(expired.refreshToken)).success);
        command.CommandText = "SELECT revoked_at FROM refresh_tokens WHERE id = 1;";
        Assert.Equal(DBNull.Value, await command.ExecuteScalarAsync());
        Assert.True((await auth.RefreshAsync(other.refreshToken)).success);
    }

    [Fact]
    public async Task RefreshTokenIsNotStoredInPlainText()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        await RegisterAsync(client, "storage@example.com", "s3cr3tpass");
        var tokens = await LoginAsync(client, "storage@example.com", "s3cr3tpass");

        await using var conn = new SqliteConnection($"Data Source={app.DatabasePath}");
        await conn.OpenAsync();

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT token_hash FROM refresh_tokens LIMIT 1;";

        var storedTokenHash = Assert.IsType<string>(await cmd.ExecuteScalarAsync());
        Assert.NotEqual(tokens.RefreshToken, storedTokenHash);
        Assert.False(storedTokenHash.Contains(tokens.RefreshToken, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExpiredAccessTokenIsRejected()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        var expiredToken = CreateJwt(DateTime.UtcNow.AddMinutes(-30), DateTime.UtcNow.AddMinutes(-15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", expiredToken);

        var response = await client.GetAsync("/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AuthEndpointsAreRateLimited()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        var responses = new List<HttpResponseMessage>();
        for (var i = 0; i < 11; i++)
        {
            responses.Add(await client.PostAsJsonAsync("/login", new
            {
                email = "rate-limit@example.com",
                password = "wrong-pass"
            }));
        }

        Assert.Contains(responses, response => response.StatusCode == HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task LoginDoesNotRevealWhetherEmailExists()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        await RegisterAsync(client, "bob@example.com", "correct-pass");

        var wrongPassword = await client.PostAsJsonAsync("/login", new
        {
            email = "bob@example.com",
            password = "wrong-pass"
        });
        var missingUser = await client.PostAsJsonAsync("/login", new
        {
            email = "missing@example.com",
            password = "wrong-pass"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, missingUser.StatusCode);
    }

    [Fact]
    public async Task LegacyRefreshTokenSchemaIsMigratedAndInvalidated()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"loginapp-legacy-{Guid.NewGuid():N}.db");
        var database = new Database($"Data Source={databasePath}");

        await CreateLegacyDatabaseAsync(databasePath);
        await database.InitializeAsync();

        await using var conn = new SqliteConnection($"Data Source={databasePath}");
        await conn.OpenAsync();

        await using var columns = conn.CreateCommand();
        columns.CommandText = "PRAGMA table_info(refresh_tokens);";
        await using var reader = await columns.ExecuteReaderAsync();
        var columnNames = new List<string>();
        while (await reader.ReadAsync())
            columnNames.Add(reader.GetString(1));

        Assert.Contains("token_hash", columnNames);
        Assert.DoesNotContain("token", columnNames);

        await using var tokenState = conn.CreateCommand();
        tokenState.CommandText = "SELECT token_hash, revoked_at FROM refresh_tokens LIMIT 1;";
        await using var stateReader = await tokenState.ExecuteReaderAsync();

        Assert.True(await stateReader.ReadAsync());
        Assert.StartsWith("legacy-invalidated-", stateReader.GetString(0), StringComparison.Ordinal);
        Assert.False(stateReader.IsDBNull(1));
    }

    [Fact]
    public async Task CurrentHashedTokenRemainsUsableAfterFamilyMigration()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();
        var auth = app.Services.GetRequiredService<AuthService>();
        await auth.RegisterAsync("upgrade@example.com", "s3cr3tpass");
        var tokens = await auth.LoginAsync("upgrade@example.com", "s3cr3tpass");
        // Reproduce the pre-family hashed schema, only in this temporary test DB.
        await using (var conn = new SqliteConnection($"Data Source={app.DatabasePath}"))
        {
            await conn.OpenAsync();
            await using var downgrade = conn.CreateCommand();
            downgrade.CommandText = "DROP INDEX ix_refresh_tokens_family; ALTER TABLE refresh_tokens DROP COLUMN family_id;";
            await downgrade.ExecuteNonQueryAsync();
        }
        await app.Services.GetRequiredService<Database>().InitializeAsync();
        Assert.True((await auth.RefreshAsync(tokens.refreshToken)).success);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FamilyMigrationPreservesExistingRowsAndIsIdempotent(bool legacy)
    {
        var path = Path.Combine(Path.GetTempPath(), $"loginapp-family-{Guid.NewGuid():N}.db");
        await CreateLegacyDatabaseAsync(path);
        await using var conn = new SqliteConnection($"Data Source={path};Pooling=False");
        await conn.OpenAsync();
        if (!legacy)
        {
            await using var prepare = conn.CreateCommand();
            prepare.CommandText = "ALTER TABLE refresh_tokens RENAME COLUMN token TO token_hash;" +
                "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (1, 'second-hash', '2999-01-01');";
            await prepare.ExecuteNonQueryAsync();
        }
        var db = new Database($"Data Source={path};Pooling=False");
        await db.InitializeAsync();
        await using var query = conn.CreateCommand();
        query.CommandText = "SELECT family_id FROM refresh_tokens ORDER BY id;";
        var families = new List<string>();
        await using (var reader = await query.ExecuteReaderAsync())
            while (await reader.ReadAsync())
                families.Add(reader.GetString(0));
        Assert.All(families, family => Assert.False(string.IsNullOrWhiteSpace(family)));
        Assert.Equal(legacy ? 1 : 2, families.Distinct().Count());
        await db.InitializeAsync();
        var after = new List<string>();
        await using (var reader = await query.ExecuteReaderAsync())
            while (await reader.ReadAsync())
                after.Add(reader.GetString(0));
        Assert.Equal(families, after);
        query.CommandText = "SELECT COUNT(*) FROM refresh_tokens WHERE revoked_at IS NULL;";
        Assert.Equal(legacy ? 0L : 2L, (long)(await query.ExecuteScalarAsync())!);
        await conn.CloseAsync();
        File.Delete(path);
    }

    [Fact]
    public void TokenBlocklistOnlyBlocksUntilExpiry()
    {
        var blocklist = new TokenBlocklist();

        blocklist.Block("active", DateTime.UtcNow.AddMinutes(5));
        blocklist.Block("expired", DateTime.UtcNow.AddMinutes(-5));

        Assert.True(blocklist.IsBlocked("active"));
        Assert.False(blocklist.IsBlocked("expired"));
        Assert.False(blocklist.IsBlocked("missing"));
    }

    [Fact]
    public async Task RegisterRejectsInvalidEmailAndShortPassword()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        var invalidEmail = await client.PostAsJsonAsync("/register", new
        {
            email = "not-an-email",
            password = "s3cr3tpass"
        });
        var shortPassword = await client.PostAsJsonAsync("/register", new
        {
            email = "short@example.com",
            password = "short"
        });

        Assert.Equal(HttpStatusCode.BadRequest, invalidEmail.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, shortPassword.StatusCode);
    }

    [Fact]
    public async Task EndpointsRejectMissingRequiredPayloadFields()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        var register = await client.PostAsJsonAsync("/register", new
        {
            email = "",
            password = ""
        });
        var login = await client.PostAsJsonAsync("/login", new
        {
            email = "",
            password = ""
        });
        var refresh = await client.PostAsJsonAsync("/refresh", new
        {
            refreshToken = ""
        });

        Assert.Equal(HttpStatusCode.BadRequest, register.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, login.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
    }

    [Fact]
    public async Task DuplicateRegistrationReturnsConflict()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        await RegisterAsync(client, "duplicate@example.com", "s3cr3tpass");
        var duplicate = await client.PostAsJsonAsync("/register", new
        {
            email = "DUPLICATE@example.com",
            password = "s3cr3tpass"
        });

        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
    }

    [Fact]
    public void JwtSecretValidatorRejectsWeakDefaultAndProductionDevSecrets()
    {
        var development = new TestEnvironment("Development");
        var production = new TestEnvironment("Production");

        Assert.Throws<InvalidOperationException>(() => JwtSecretValidator.Validate("short", development));
        Assert.Throws<InvalidOperationException>(() =>
            JwtSecretValidator.Validate("CHANGE_THIS_TO_A_SECURE_RANDOM_SECRET_AT_LEAST_32_CHARS", development));
        Assert.Throws<InvalidOperationException>(() =>
            JwtSecretValidator.Validate(LoginAppFactory.JwtSecret, production));

        JwtSecretValidator.Validate("prod_secret_that_is_long_enough_and_not_marked_as_dev", production);
    }

    private static async Task<AuthTokens> LoginAsync(HttpClient client, string email, string password)
    {
        var response = await client.PostAsJsonAsync("/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var tokens = await response.Content.ReadFromJsonAsync<AuthTokens>();
        Assert.NotNull(tokens);
        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));
        return tokens;
    }

    private static async Task RegisterAsync(HttpClient client, string email, string password)
    {
        var response = await client.PostAsJsonAsync("/register", new { email, password });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private static string CreateJwt(DateTime notBefore, DateTime expires)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(LoginAppFactory.JwtSecret));
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "LoginApp",
            Audience = "LoginApp",
            NotBefore = notBefore,
            Expires = expires,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "1"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
            })
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static async Task CreateLegacyDatabaseAsync(string databasePath)
    {
        await using var conn = new SqliteConnection($"Data Source={databasePath}");
        await conn.OpenAsync();

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT    NOT NULL,
                password_salt TEXT    NOT NULL,
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE refresh_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token      TEXT    NOT NULL UNIQUE,
                expires_at TEXT    NOT NULL,
                revoked_at TEXT,
                created_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            INSERT INTO users (email, password_hash, password_salt)
            VALUES ('legacy@example.com', 'hash', 'salt');

            INSERT INTO refresh_tokens (user_id, token, expires_at)
            VALUES (1, 'plain-text-legacy-refresh-token', '2999-01-01T00:00:00.0000000Z');
            """;
        await cmd.ExecuteNonQueryAsync();
    }

    private sealed record AuthTokens(string AccessToken, string RefreshToken);
}

internal sealed class LoginAppFactory : WebApplicationFactory<Program>
{
    public const string JwtSecret = "DEV_ONLY_local_loginapp_secret_please_override_in_production_64_chars";

    private readonly string _databasePath = Path.Combine(Path.GetTempPath(), $"loginapp-tests-{Guid.NewGuid():N}.db");

    public string DatabasePath => _databasePath;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration(config =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = $"Data Source={_databasePath}",
                ["Jwt:Secret"] = JwtSecret,
                ["RefreshTokens:HashKey"] = JwtSecret
            });
        });

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<Database>();
            services.AddSingleton(new Database($"Data Source={_databasePath}"));
        });
    }
}

internal sealed class TestEnvironment : IWebHostEnvironment
{
    public TestEnvironment(string environmentName)
    {
        EnvironmentName = environmentName;
    }

    public string ApplicationName { get; set; } = "LoginApp.Tests";
    public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    public string ContentRootPath { get; set; } = Directory.GetCurrentDirectory();
    public string EnvironmentName { get; set; }
    public string WebRootPath { get; set; } = Directory.GetCurrentDirectory();
    public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
}
