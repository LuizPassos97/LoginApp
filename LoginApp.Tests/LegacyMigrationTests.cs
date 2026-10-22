using System.Text.Json;
using LoginApp.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace LoginApp.Tests;

public sealed class LegacyMigrationTests
{
    [Theory]
    [InlineData(true, 1299)] // SQLITE_CONSTRAINT_NOTNULL
    [InlineData(false, 787)] // SQLITE_CONSTRAINT_FOREIGNKEY
    public async Task FailedMigrationPreservesLegacyDatabaseAndCanBeRetried(
        bool missingExpiry, int expectedConstraint)
    {
        await using var fixture = new TemporaryDatabase();
        await fixture.ExecuteAsync("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT,
                revoked_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            INSERT INTO users VALUES (1, 'legacy@example.com', 'hash', 'salt', '2020-01-01');
            INSERT INTO refresh_tokens VALUES
                (10, 1, 'legacy-active', '2999-01-01', NULL, '2021-01-01'),
                (20, 1, 'legacy-revoked', '2999-02-01', '2022-01-01', '2021-02-01');
            """);
        // Historical corruption is seeded on a separate connection with FK checks disabled.
        // The application must still enforce both constraints during the real migration.
        await fixture.ExecuteAsync(missingExpiry
            ? "UPDATE refresh_tokens SET expires_at = NULL WHERE id = 20;"
            : "UPDATE refresh_tokens SET user_id = 999 WHERE id = 20;");

        var schemaBefore = await fixture.QueryAsync(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name;");
        var tokensBefore = await fixture.QueryAsync("SELECT * FROM refresh_tokens ORDER BY id;");
        var usersBefore = await fixture.QueryAsync("SELECT * FROM users ORDER BY id;");
        var database = new Database(fixture.ConnectionString);

        var failure = await Assert.ThrowsAsync<SqliteException>(() => database.InitializeAsync());

        Assert.Equal(19, failure.SqliteErrorCode);
        Assert.Equal(expectedConstraint, failure.SqliteExtendedErrorCode);
        Assert.Equal(schemaBefore, await fixture.QueryAsync(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name;"));
        Assert.Equal(tokensBefore, await fixture.QueryAsync("SELECT * FROM refresh_tokens ORDER BY id;"));
        Assert.Equal(usersBefore, await fixture.QueryAsync("SELECT * FROM users ORDER BY id;"));

        await fixture.ExecuteAsync(missingExpiry
            ? "UPDATE refresh_tokens SET expires_at = '2999-02-01' WHERE id = 20;"
            : "UPDATE refresh_tokens SET user_id = 1 WHERE id = 20;");
        await database.InitializeAsync();

        Assert.Equal(usersBefore, await fixture.QueryAsync("SELECT * FROM users ORDER BY id;"));
        Assert.Equal("[[1,\"legacy-invalidated-10\",\"2999-01-01\",\"2021-01-01\"],[1,\"legacy-invalidated-20\",\"2999-02-01\",\"2021-02-01\"]]",
            await fixture.QueryAsync("SELECT user_id, token_hash, expires_at, created_at FROM refresh_tokens ORDER BY token_hash;"));
        Assert.Equal("[[0]]", await fixture.QueryAsync("SELECT COUNT(*) FROM refresh_tokens WHERE revoked_at IS NULL;"));
        Assert.Equal("[[\"2022-01-01\"]]", await fixture.QueryAsync(
            "SELECT revoked_at FROM refresh_tokens WHERE token_hash = 'legacy-invalidated-20';"));
        Assert.Equal("[[0]]", await fixture.QueryAsync(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'refresh_tokens_legacy';"));
        var columns = await fixture.QueryAsync("SELECT name FROM pragma_table_info('refresh_tokens');");
        Assert.Contains("\"token_hash\"", columns, StringComparison.Ordinal);
        Assert.DoesNotContain("\"token\"", columns, StringComparison.Ordinal);
        Assert.Equal("[]", await fixture.QueryAsync("PRAGMA foreign_key_check;"));

        var migratedSchema = await fixture.QueryAsync(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name;");
        var migratedTokens = await fixture.QueryAsync("SELECT * FROM refresh_tokens ORDER BY id;");
        await database.InitializeAsync();
        Assert.Equal(migratedSchema, await fixture.QueryAsync(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name;"));
        Assert.Equal(migratedTokens, await fixture.QueryAsync("SELECT * FROM refresh_tokens ORDER BY id;"));

        await using var connection = await database.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_keys;";
        Assert.Equal(1L, await command.ExecuteScalarAsync());
        command.CommandText = "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (999, 'orphan', '2999-01-01');";
        var foreignKeyFailure = await Assert.ThrowsAsync<SqliteException>(async () => await command.ExecuteNonQueryAsync());
        Assert.Equal(787, foreignKeyFailure.SqliteExtendedErrorCode);
        command.CommandText = "DELETE FROM users WHERE id = 1;";
        await command.ExecuteNonQueryAsync();
        command.CommandText = "SELECT COUNT(*) FROM refresh_tokens;";
        Assert.Equal(0L, await command.ExecuteScalarAsync());
    }

    private sealed class TemporaryDatabase : IAsyncDisposable
    {
        private readonly string _path;

        public TemporaryDatabase()
        {
            var temporaryDirectory = Path.GetTempPath();
            if (!Directory.Exists(temporaryDirectory))
                throw new DirectoryNotFoundException(temporaryDirectory);
            _path = Path.Combine(temporaryDirectory, $"loginapp-migration-{Guid.NewGuid():N}.db");
            ConnectionString = new SqliteConnectionStringBuilder
            {
                DataSource = _path,
                Pooling = false,
                ForeignKeys = false
            }.ToString();
        }

        public string ConnectionString { get; }

        public async Task ExecuteAsync(string sql)
        {
            await using var connection = new SqliteConnection(ConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync();
        }

        public async Task<string> QueryAsync(string sql)
        {
            await using var connection = new SqliteConnection(ConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await using var reader = await command.ExecuteReaderAsync();
            var rows = new List<object?[]>();
            while (await reader.ReadAsync())
            {
                var row = new object?[reader.FieldCount];
                for (var index = 0; index < reader.FieldCount; index++)
                    row[index] = reader.IsDBNull(index) ? null : reader.GetValue(index);
                rows.Add(row);
            }
            return JsonSerializer.Serialize(rows);
        }

        public ValueTask DisposeAsync()
        {
            File.Delete(_path);
            return ValueTask.CompletedTask;
        }
    }
}
