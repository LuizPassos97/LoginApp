using System.Collections.Concurrent;

namespace LoginApp.Services;

// In-memory blocklist for revoked JTIs. Entries expire naturally when the
// original token would have expired, keeping memory bounded to the access
// token lifetime window (15 minutes).
public sealed class TokenBlocklist
{
    private readonly ConcurrentDictionary<string, DateTime> _blocked = new();

    public void Block(string jti, DateTime tokenExpiry)
    {
        _blocked[jti] = tokenExpiry;
        Prune();
    }

    public bool IsBlocked(string jti) =>
        _blocked.TryGetValue(jti, out var expiry) && expiry > DateTime.UtcNow;

    private void Prune()
    {
        var now = DateTime.UtcNow;
        foreach (var key in _blocked.Keys)
        {
            if (_blocked.TryGetValue(key, out var exp) && exp <= now)
                _blocked.TryRemove(key, out _);
        }
    }
}
