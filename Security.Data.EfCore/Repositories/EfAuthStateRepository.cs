namespace Birdsoft.Security.Data.EfCore.Repositories;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfAuthStateRepository : IAuthStateRepository
{
    private readonly SecurityDbContext _db;

    public EfAuthStateRepository(SecurityDbContext db) => _db = db;

    public async Task CreateAsync(string state, Guid tenantId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        var entity = new AuthStateEntity
        {
            State = state,
            TenantId = tenantId,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
            UsedAt = null,
            CodeVerifier = null,
            Nonce = null,
        };

        _db.AuthStates.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
    }

    public async Task<AuthStateDto?> FindAsync(string state, CancellationToken cancellationToken = default)
    {
        var entity = await _db.AuthStates.AsNoTracking()
            .FirstOrDefaultAsync(x => x.State == state, cancellationToken);

        return entity is null ? null : ToDto(entity);
    }

    public async Task<bool> TryAttachOidcContextAsync(string state, string codeVerifier, string nonce, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        // Use raw SQL for an atomic update that works across providers.
        var affected = await _db.Database.ExecuteSqlInterpolatedAsync(
            $@"UPDATE auth_states
SET CodeVerifier = {codeVerifier}, Nonce = {nonce}
WHERE State = {state}
  AND UsedAt IS NULL
  AND ExpiresAt > {now}
  AND CodeVerifier IS NULL
  AND Nonce IS NULL;",
            cancellationToken);

        return affected == 1;
    }

    public async Task<bool> TryConsumeAsync(string state, DateTimeOffset usedAt, CancellationToken cancellationToken = default)
    {
        // Use raw SQL for an atomic update that works across providers.
        var affected = await _db.Database.ExecuteSqlInterpolatedAsync(
            $@"UPDATE auth_states
SET UsedAt = {usedAt}
WHERE State = {state}
  AND UsedAt IS NULL
  AND ExpiresAt > {usedAt};",
            cancellationToken);

        return affected == 1;
    }

    public async Task<AuthStateDto?> TryConsumeAndGetAsync(string state, DateTimeOffset usedAt, CancellationToken cancellationToken = default)
    {
        var entity = await _db.AuthStates.AsNoTracking()
            .FirstOrDefaultAsync(x => x.State == state, cancellationToken);

        if (entity is null)
        {
            return null;
        }

        if (entity.UsedAt is not null || entity.ExpiresAt <= usedAt)
        {
            return null;
        }

        var ok = await TryConsumeAsync(state, usedAt, cancellationToken);
        return ok ? ToDto(entity) with { UsedAt = usedAt } : null;
    }

    public async Task<int> DeleteExpiredOrUsedAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        // Use raw SQL to avoid provider translation gaps.
        return await _db.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM auth_states WHERE ExpiresAt <= {now} OR UsedAt IS NOT NULL;",
            cancellationToken);
    }

    private static AuthStateDto ToDto(AuthStateEntity entity)
        => new()
        {
            State = entity.State,
            TenantId = entity.TenantId,
            CreatedAt = entity.CreatedAt,
            ExpiresAt = entity.ExpiresAt,
            UsedAt = entity.UsedAt,
            CodeVerifier = entity.CodeVerifier,
            Nonce = entity.Nonce,
        };
}
