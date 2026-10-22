using Microsoft.Data.Sqlite;
using Xunit;

namespace LoginApp.Tests;

public sealed class SqliteVersionTests
{
    [Fact]
    public async Task NativeSqliteVersionIncludesCve20256965Fix()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT sqlite_version();";
        var versionText = Assert.IsType<string>(await command.ExecuteScalarAsync());
        var version = Version.Parse(versionText);

        // CVE-2025-6965 affects SQLite versions before 3.50.2.
        Assert.True(version >= new Version(3, 50, 2),
            $"SQLite {version} is vulnerable to CVE-2025-6965; version 3.50.2 or later is required.");
    }
}
