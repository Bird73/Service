namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfSessionStore : ISessionStore
{
    private readonly SecurityDbContext _db;

    public EfSessionStore(SecurityDbContext db) => _db = db;

    public async Task<Guid> CreateSessionAsync(Guid tenantId, Guid ourSubject, DateTimeOffset createdAt, CancellationToken cancellationToken = default)
    {
        // refresh_sessions are created together with the refresh token record.
        // Keep this API for compatibility; callers should create refresh session via IRefreshTokenRepository.
        _ = tenantId;
        _ = ourSubject;
        _ = createdAt;
        _ = cancellationToken;
        return Guid.NewGuid();
    }

    public async Task<bool> IsSessionActiveAsync(Guid tenantId, Guid sessionId, CancellationToken cancellationToken = default)
    {
        return await _db.RefreshSessions.AsNoTracking()
            .AnyAsync(x => x.TenantId == tenantId && x.SessionId == sessionId && x.RevokedAt == null, cancellationToken);
    }

    public async Task<bool> TerminateSessionAsync(Guid tenantId, Guid sessionId, DateTimeOffset terminatedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        var updated = await _db.RefreshSessions
            .Where(x => x.TenantId == tenantId && x.SessionId == sessionId && x.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.RevokedAt, terminatedAt)
                .SetProperty(x => x.RevocationReason, reason),
                cancellationToken);

        return updated > 0;
    }

    public async Task<int> TerminateAllAsync(Guid tenantId, Guid ourSubject, DateTimeOffset terminatedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        return await _db.RefreshSessions
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject && x.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.RevokedAt, terminatedAt)
                .SetProperty(x => x.RevocationReason, reason),
                cancellationToken);
    }
}
