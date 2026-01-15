namespace Birdsoft.Security.Data.EfCore.Repositories;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

public sealed class EfRefreshTokenRepository : IRefreshTokenRepository
{
    private readonly SecurityDbContext _db;

    public EfRefreshTokenRepository(SecurityDbContext db) => _db = db;

    public async Task<RefreshTokenDto> CreateAsync(
        Guid tenantId,
        Guid ourSubject,
        Guid sessionId,
        string tokenLookup,
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
            TokenLookup = tokenLookup,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            RevokedAt = null,
            ReplacedByRefreshTokenId = null,
            RevocationReason = null,
            IssuedTenantTokenVersion = issuedTenantTokenVersion,
            IssuedSubjectTokenVersion = issuedSubjectTokenVersion,
        };

        _db.RefreshSessions.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return ToDto(entity);
    }

    public async Task<RefreshTokenDto?> FindByHashAsync(Guid tenantId, string tokenLookup, string tokenHash, CancellationToken cancellationToken = default)
    {
        // Tenant-aware lookup first, then constant-time compare in-memory.
        var candidates = await _db.RefreshSessions.AsNoTracking()
            .Where(x => x.TenantId == tenantId && x.TokenLookup == tokenLookup)
            .ToListAsync(cancellationToken);

        if (candidates.Count == 0)
        {
            return null;
        }

        var expected = DecodeBase64Url(tokenHash);
        foreach (var c in candidates)
        {
            var actual = DecodeBase64Url(c.TokenHash);
            if (CryptographicOperations.FixedTimeEquals(expected, actual))
            {
                return ToDto(c);
            }
        }

        return null;
    }

    public async Task<RefreshTokenDto?> TryRotateAsync(
        Guid tenantId,
        Guid ourSubject,
        Guid currentSessionId,
        string currentTokenLookup,
        string currentTokenHash,
        Guid newSessionId,
        string newTokenLookup,
        string newTokenHash,
        DateTimeOffset expiresAt,
        DateTimeOffset now,
        int issuedTenantTokenVersion,
        int issuedSubjectTokenVersion,
        string? revokeReason = null,
        CancellationToken cancellationToken = default)
    {
        await using var tx = await _db.Database.BeginTransactionAsync(cancellationToken);

        var newEntity = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            OurSubject = ourSubject,
            SessionId = newSessionId,
            TokenHash = newTokenHash,
            TokenLookup = newTokenLookup,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            RevokedAt = null,
            ReplacedByRefreshTokenId = null,
            RevocationReason = null,
            IssuedTenantTokenVersion = issuedTenantTokenVersion,
            IssuedSubjectTokenVersion = issuedSubjectTokenVersion,
        };

        _db.RefreshSessions.Add(newEntity);
        await _db.SaveChangesAsync(cancellationToken);

        // Revoke the old session row. Compare by (tenant, session_id, subject) plus token lookup/hash.
        // The token hash comparison is done by token_lookup filtering + a normal equality check here,
        // since the computed hash is already HMAC/SHA output and not secret. The constant-time requirement
        // is satisfied in FindByHashAsync.
        var affected = await _db.RefreshSessions
            .Where(x => x.TenantId == tenantId
                        && x.OurSubject == ourSubject
                        && x.SessionId == currentSessionId
                        && x.TokenLookup == currentTokenLookup
                        && x.TokenHash == currentTokenHash
                        && x.RevokedAt == null)
            .ExecuteUpdateAsync(
                s => s
                    .SetProperty(x => x.RevokedAt, now)
                    .SetProperty(x => x.ReplacedByRefreshTokenId, newEntity.Id)
                    .SetProperty(x => x.RevocationReason, revokeReason),
                cancellationToken);

        if (affected != 1)
        {
            await tx.RollbackAsync(cancellationToken);
            return null;
        }

        await tx.CommitAsync(cancellationToken);
        return ToDto(newEntity);
    }

    public async Task<bool> RevokeAsync(
        Guid tenantId,
        Guid ourSubject,
        Guid sessionId,
        string tokenLookup,
        string tokenHash,
        DateTimeOffset revokedAt,
        string? revokeReason = null,
        Guid? replacedBySessionRecordId = null,
        CancellationToken cancellationToken = default)
    {
        var affected = await _db.RefreshSessions
            .Where(x => x.TenantId == tenantId
                        && x.OurSubject == ourSubject
                        && x.SessionId == sessionId
                        && x.TokenLookup == tokenLookup
                        && x.TokenHash == tokenHash
                        && x.RevokedAt == null)
            .ExecuteUpdateAsync(
                s => s
                    .SetProperty(x => x.RevokedAt, revokedAt)
                    .SetProperty(x => x.ReplacedByRefreshTokenId, replacedBySessionRecordId)
                    .SetProperty(x => x.RevocationReason, revokeReason),
                cancellationToken);

        return affected == 1;
    }

    public async Task<int> RevokeAllBySubjectAsync(Guid tenantId, Guid ourSubject, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        return await _db.RefreshSessions
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject && x.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, revokedAt), cancellationToken);
    }

    public async Task<int> RevokeAllBySessionAsync(Guid tenantId, Guid sessionId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        return await _db.RefreshSessions
            .Where(x => x.TenantId == tenantId && x.SessionId == sessionId && x.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, revokedAt), cancellationToken);
    }

    public async Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        return await _db.RefreshSessions
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
            TokenLookup = entity.TokenLookup,
            TokenHash = entity.TokenHash,
            CreatedAt = entity.CreatedAt,
            ExpiresAt = entity.ExpiresAt,
            RevokedAt = entity.RevokedAt,
            ReplacedByRefreshTokenId = entity.ReplacedByRefreshTokenId,
            RevocationReason = entity.RevocationReason,
            IssuedTenantTokenVersion = entity.IssuedTenantTokenVersion,
            IssuedSubjectTokenVersion = entity.IssuedSubjectTokenVersion,
        };

    private static byte[] DecodeBase64Url(string s)
    {
        // Base64Url without padding.
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }

        return Convert.FromBase64String(s);
    }
}
