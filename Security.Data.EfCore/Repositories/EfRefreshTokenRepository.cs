namespace Birdsoft.Security.Data.EfCore.Repositories;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfRefreshTokenRepository : IRefreshTokenRepository
{
    private readonly SecurityDbContext _db;

    public EfRefreshTokenRepository(SecurityDbContext db) => _db = db;

    public async Task<RefreshTokenDto> CreateAsync(
        Guid tenantId,
        Guid ourSubject,
        Guid sessionId,
        string tokenHash,
        DateTimeOffset expiresAt,
        int issuedTenantTokenVersion,
        int issuedSubjectTokenVersion,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        var entity = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            OurSubject = ourSubject,
            SessionId = sessionId,
            TokenHash = tokenHash,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            RevokedAt = null,
            ReplacedByRefreshTokenId = null,
            IssuedTenantTokenVersion = issuedTenantTokenVersion,
            IssuedSubjectTokenVersion = issuedSubjectTokenVersion,
        };

        _db.RefreshTokens.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return ToDto(entity);
    }

    public async Task<RefreshTokenDto?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        var entity = await _db.RefreshTokens.AsNoTracking()
            .FirstOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken);

        return entity is null ? null : ToDto(entity);
    }

    public async Task<bool> RevokeAsync(
        Guid tenantId,
        Guid ourSubject,
        string tokenHash,
        DateTimeOffset revokedAt,
        Guid? replacedByTokenId = null,
        CancellationToken cancellationToken = default)
    {
        var affected = await _db.RefreshTokens
            .Where(x => x.TenantId == tenantId
                        && x.OurSubject == ourSubject
                        && x.TokenHash == tokenHash
                        && x.RevokedAt == null)
            .ExecuteUpdateAsync(
                s => s
                    .SetProperty(x => x.RevokedAt, revokedAt)
                    .SetProperty(x => x.ReplacedByRefreshTokenId, replacedByTokenId),
                cancellationToken);

        return affected == 1;
    }

    public async Task<int> RevokeAllBySubjectAsync(Guid tenantId, Guid ourSubject, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        return await _db.RefreshTokens
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject && x.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, revokedAt), cancellationToken);
    }

    public async Task<int> RevokeAllBySessionAsync(Guid tenantId, Guid sessionId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        return await _db.RefreshTokens
            .Where(x => x.TenantId == tenantId && x.SessionId == sessionId && x.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, revokedAt), cancellationToken);
    }

    public async Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        return await _db.RefreshTokens
            .Where(x => x.ExpiresAt <= now)
            .ExecuteDeleteAsync(cancellationToken);
    }

    private static RefreshTokenDto ToDto(RefreshTokenEntity entity)
        => new()
        {
            Id = entity.Id,
            TenantId = entity.TenantId,
            OurSubject = entity.OurSubject,
            SessionId = entity.SessionId,
            TokenHash = entity.TokenHash,
            CreatedAt = entity.CreatedAt,
            ExpiresAt = entity.ExpiresAt,
            RevokedAt = entity.RevokedAt,
            ReplacedByRefreshTokenId = entity.ReplacedByRefreshTokenId,
            IssuedTenantTokenVersion = entity.IssuedTenantTokenVersion,
            IssuedSubjectTokenVersion = entity.IssuedSubjectTokenVersion,
        };
}
