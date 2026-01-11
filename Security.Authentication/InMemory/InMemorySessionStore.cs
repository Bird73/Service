namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions.Stores;
using System.Collections.Concurrent;

public sealed class InMemorySessionStore : ISessionStore
{
    private sealed record SessionRecord(Guid TenantId, Guid OurSubject, DateTimeOffset CreatedAt, DateTimeOffset? TerminatedAt, string? Reason);

    private readonly ConcurrentDictionary<(Guid TenantId, Guid SessionId), SessionRecord> _sessions = new();

    public Task<Guid> CreateSessionAsync(Guid tenantId, Guid ourSubject, DateTimeOffset createdAt, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var sessionId = Guid.NewGuid();
        _sessions[(tenantId, sessionId)] = new SessionRecord(tenantId, ourSubject, createdAt, TerminatedAt: null, Reason: null);
        return Task.FromResult(sessionId);
    }

    public Task<bool> IsSessionActiveAsync(Guid tenantId, Guid sessionId, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        return Task.FromResult(_sessions.TryGetValue((tenantId, sessionId), out var rec) && rec.TerminatedAt is null);
    }

    public Task<bool> TerminateSessionAsync(Guid tenantId, Guid sessionId, DateTimeOffset terminatedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var key = (tenantId, sessionId);
        if (!_sessions.TryGetValue(key, out var rec))
        {
            return Task.FromResult(false);
        }

        if (rec.TerminatedAt is not null)
        {
            return Task.FromResult(true);
        }

        _sessions[key] = rec with { TerminatedAt = terminatedAt, Reason = reason };
        return Task.FromResult(true);
    }

    public Task<int> TerminateAllAsync(Guid tenantId, Guid ourSubject, DateTimeOffset terminatedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var count = 0;

        foreach (var (key, rec) in _sessions)
        {
            if (key.TenantId == tenantId && rec.OurSubject == ourSubject && rec.TerminatedAt is null)
            {
                _sessions[key] = rec with { TerminatedAt = terminatedAt, Reason = reason };
                count++;
            }
        }

        return Task.FromResult(count);
    }
}
