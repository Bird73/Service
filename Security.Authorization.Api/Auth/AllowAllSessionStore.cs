namespace Birdsoft.Security.Authorization.Api.Auth;

using Birdsoft.Security.Abstractions.Stores;

public sealed class AllowAllSessionStore : ISessionStore
{
    public Task<Guid> CreateSessionAsync(Guid tenantId, Guid ourSubject, DateTimeOffset createdAt, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = ourSubject;
        _ = createdAt;
        _ = cancellationToken;
        return Task.FromResult(Guid.NewGuid());
    }

    public Task<bool> IsSessionActiveAsync(Guid tenantId, Guid sessionId, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = sessionId;
        _ = cancellationToken;
        return Task.FromResult(true);
    }

    public Task<bool> TerminateSessionAsync(Guid tenantId, Guid sessionId, DateTimeOffset terminatedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = sessionId;
        _ = terminatedAt;
        _ = reason;
        _ = cancellationToken;
        return Task.FromResult(true);
    }

    public Task<int> TerminateAllAsync(Guid tenantId, Guid ourSubject, DateTimeOffset terminatedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = ourSubject;
        _ = terminatedAt;
        _ = reason;
        _ = cancellationToken;
        return Task.FromResult(0);
    }
}
