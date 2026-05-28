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
    public async Task ConcurrentRefreshRequestsOnlyConsumeTokenOnce()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();

        await RegisterAsync(client, "race@example.com", "s3cr3tpass");
        var tokens = await LoginAsync(client, "race@example.com", "s3cr3tpass");

        var refreshTasks = Enumerable.Range(0, 2)
            .Select(_ => client.PostAsJsonAsync("/refresh", new { refreshToken = tokens.RefreshToken }))
            .ToArray();

        var responses = await Task.WhenAll(refreshTasks);

        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.OK));
        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.Unauthorized));
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
                ["ConnectionStrings:Default"] = $"Data Source={_databasePath}"
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
