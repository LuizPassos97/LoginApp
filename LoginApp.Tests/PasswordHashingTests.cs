using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Xunit;

namespace LoginApp.Tests;

public sealed class PasswordHashingTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task LegacyHashIsUpgradedOnlyAfterSuccessfulLogin(bool validPassword)
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();
        await using var connection = new SqliteConnection($"Data Source={app.DatabasePath}");
        await connection.OpenAsync();
        var salt = RandomNumberGenerator.GetBytes(32);
        var legacyHash = Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(
            "legacy-password", salt, 100_000, HashAlgorithmName.SHA256, 32));
        await using var insert = connection.CreateCommand();
        insert.CommandText = "INSERT INTO users (email, password_hash, password_salt) VALUES (@email, @hash, @salt);";
        insert.Parameters.AddWithValue("@email", "legacy@example.com");
        insert.Parameters.AddWithValue("@hash", legacyHash);
        insert.Parameters.AddWithValue("@salt", Convert.ToBase64String(salt));
        await insert.ExecuteNonQueryAsync();

        var response = await client.PostAsJsonAsync("/login", new
        {
            email = "legacy@example.com",
            password = validPassword ? "legacy-password" : "wrong-password"
        });
        Assert.Equal(validPassword ? HttpStatusCode.OK : HttpStatusCode.Unauthorized, response.StatusCode);
        await using var read = connection.CreateCommand();
        read.CommandText = "SELECT password_hash FROM users;";
        var storedHash = Assert.IsType<string>(await read.ExecuteScalarAsync());
        if (validPassword)
        {
            Assert.StartsWith("pbkdf2-sha256$600000$", storedHash);
            var secondLogin = await client.PostAsJsonAsync("/login", new
            {
                email = "legacy@example.com", password = "legacy-password"
            });
            Assert.Equal(HttpStatusCode.OK, secondLogin.StatusCode);
        }
        else
        {
            Assert.Equal(legacyHash, storedHash);
        }
    }

    [Theory]
    [InlineData("legacy")]
    [InlineData("current")]
    [InlineData("unknown")]
    public async Task FailedLoginDoesNotChangeStoredCredentialsOrSessions(string account)
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();
        await using var connection = new SqliteConnection($"Data Source={app.DatabasePath}");
        await connection.OpenAsync();
        var salt = RandomNumberGenerator.GetBytes(32);
        var current = account != "legacy";
        var hash = (current ? "pbkdf2-sha256$600000$" : "") +
            Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(
                "correct-password", salt, current ? 600_000 : 100_000, HashAlgorithmName.SHA256, 32));
        await using var seed = connection.CreateCommand();
        seed.CommandText = """
            INSERT INTO users (email, password_hash, password_salt) VALUES ('existing@example.com', @hash, @salt);
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (last_insert_rowid(), 'fictional-existing-session', '2099-01-01T00:00:00Z');
            """;
        seed.Parameters.AddWithValue("@hash", hash);
        seed.Parameters.AddWithValue("@salt", Convert.ToBase64String(salt));
        await seed.ExecuteNonQueryAsync();
        var before = await ReadStoredStateAsync(connection);

        using var response = await client.PostAsJsonAsync("/login", new
        {
            email = account == "unknown" ? "unknown@example.com" : "existing@example.com",
            password = "wrong-password"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.Equal(before, await ReadStoredStateAsync(connection));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
    }

    private static async Task<string> ReadStoredStateAsync(SqliteConnection connection)
    {
        var rows = new List<string[]>();
        foreach (var table in new[] { "users", "refresh_tokens" })
        {
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM {table} ORDER BY id;";
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                rows.Add(Enumerable.Range(0, reader.FieldCount)
                    .Select(i => reader.GetValue(i).ToString()!).ToArray());
        }
        return System.Text.Json.JsonSerializer.Serialize(rows);
    }

    [Fact]
    public async Task RegistrationStoresVersionedHashWithSixHundredThousandIterations()
    {
        await using var app = new LoginAppFactory();
        using var client = app.CreateClient();
        var response = await client.PostAsJsonAsync("/register", new
        {
            email = "hash@example.com", password = "correct-password"
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        await using var connection = new SqliteConnection($"Data Source={app.DatabasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT password_hash, password_salt FROM users;";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        var storedHash = reader.GetString(0);
        Assert.StartsWith("pbkdf2-sha256$600000$", storedHash);
        var expected = Rfc2898DeriveBytes.Pbkdf2("correct-password",
            Convert.FromBase64String(reader.GetString(1)), 600_000, HashAlgorithmName.SHA256, 32);
        Assert.Equal(Convert.ToBase64String(expected), storedHash.Split('$')[2]);
    }
}
