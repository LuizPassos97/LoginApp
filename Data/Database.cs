using Microsoft.Data.Sqlite;

namespace LoginApp.Data;

public sealed class Database
{
    private readonly string _connectionString;

    public Database(string connectionString)
    {
        _connectionString = connectionString;
    }

    public SqliteConnection GetConnection() => new SqliteConnection(_connectionString);

    public async Task<SqliteConnection> OpenConnectionAsync()
    {
        var conn = GetConnection();
        await conn.OpenAsync();

        await using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys = ON;";
        await pragma.ExecuteNonQueryAsync();

        return conn;
    }

    public async Task InitializeAsync()
    {
        await using var conn = await OpenConnectionAsync();

        await using var cmdUsers = conn.CreateCommand();
        cmdUsers.CommandText = """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT    NOT NULL,
                password_salt TEXT    NOT NULL,
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );
            """;
        await cmdUsers.ExecuteNonQueryAsync();

        await EnsureRefreshTokenSchemaAsync(conn);
    }

    private static async Task EnsureRefreshTokenSchemaAsync(SqliteConnection conn)
    {
        if (!await RefreshTokenTableExistsAsync(conn))
        {
            await CreateRefreshTokenTableAsync(conn);
            return;
        }

        if (await RefreshTokenTableHasColumnAsync(conn, "token_hash"))
            return;

        await using var disableForeignKeys = conn.CreateCommand();
        disableForeignKeys.CommandText = "PRAGMA foreign_keys = OFF;";
        await disableForeignKeys.ExecuteNonQueryAsync();

        await using var rename = conn.CreateCommand();
        rename.CommandText = "ALTER TABLE refresh_tokens RENAME TO refresh_tokens_legacy;";
        await rename.ExecuteNonQueryAsync();

        await CreateRefreshTokenTableAsync(conn);

        await using var migrate = conn.CreateCommand();
        migrate.CommandText = """
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked_at, created_at)
            SELECT user_id,
                   'legacy-invalidated-' || id,
                   expires_at,
                   COALESCE(revoked_at, datetime('now')),
                   created_at
              FROM refresh_tokens_legacy;
            """;
        await migrate.ExecuteNonQueryAsync();

        await using var dropLegacy = conn.CreateCommand();
        dropLegacy.CommandText = "DROP TABLE refresh_tokens_legacy;";
        await dropLegacy.ExecuteNonQueryAsync();

        await using var enableForeignKeys = conn.CreateCommand();
        enableForeignKeys.CommandText = "PRAGMA foreign_keys = ON;";
        await enableForeignKeys.ExecuteNonQueryAsync();
    }

    private static async Task CreateRefreshTokenTableAsync(SqliteConnection conn)
    {
        await using var cmdTokens = conn.CreateCommand();
        cmdTokens.CommandText = """
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT    NOT NULL UNIQUE,
                expires_at TEXT    NOT NULL,
                revoked_at TEXT,
                created_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );
            """;
        await cmdTokens.ExecuteNonQueryAsync();
    }

    private static async Task<bool> RefreshTokenTableExistsAsync(SqliteConnection conn)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT 1
              FROM sqlite_master
             WHERE type = 'table' AND name = 'refresh_tokens';
            """;

        var result = await cmd.ExecuteScalarAsync();
        return result is not null;
    }

    private static async Task<bool> RefreshTokenTableHasColumnAsync(SqliteConnection conn, string column)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA table_info(refresh_tokens);";

        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
