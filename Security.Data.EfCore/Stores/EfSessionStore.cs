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
        var sessionId = Guid.NewGuid();
        var entity = new TokenSessionEntity
        {
            TenantId = tenantId,
            SessionId = sessionId,
            OurSubject = ourSubject,
            CreatedAt = createdAt,
            TerminatedAt = null,
            TerminationReason = null,
        };

        _db.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
        return sessionId;
    }

    public async Task<bool> IsSessionActiveAsync(Guid tenantId, Guid sessionId, CancellationToken cancellationToken = default)
    {
        return await _db.Set<TokenSessionEntity>().AsNoTracking()
            .AnyAsync(x => x.TenantId == tenantId && x.SessionId == sessionId && x.TerminatedAt == null, cancellationToken);
    }

    public async Task<bool> TerminateSessionAsync(Guid tenantId, Guid sessionId, DateTimeOffset terminatedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        var updated = await _db.Set<TokenSessionEntity>()
            .Where(x => x.TenantId == tenantId && x.SessionId == sessionId && x.TerminatedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.TerminatedAt, terminatedAt)
                .SetProperty(x => x.TerminationReason, reason),
                cancellationToken);

        return updated > 0;
    }

    public async Task<int> TerminateAllAsync(Guid tenantId, Guid ourSubject, DateTimeOffset terminatedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        return await _db.Set<TokenSessionEntity>()
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject && x.TerminatedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.TerminatedAt, terminatedAt)
                .SetProperty(x => x.TerminationReason, reason),
                cancellationToken);
    }
}
