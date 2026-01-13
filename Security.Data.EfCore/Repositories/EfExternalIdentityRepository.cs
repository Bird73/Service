namespace Birdsoft.Security.Data.EfCore.Repositories;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfExternalIdentityRepository : IExternalIdentityRepository
{
    private readonly SecurityDbContext _db;

    public EfExternalIdentityRepository(SecurityDbContext db) => _db = db;

    public async Task<ExternalIdentityDto?> FindAsync(
        Guid tenantId,
        string provider,
        string issuer,
        string providerSub,
        CancellationToken cancellationToken = default)
    {
        var entity = await _db.ExternalIdentities.AsNoTracking()
            .FirstOrDefaultAsync(
                x => x.TenantId == tenantId
                     && x.Provider == provider
                     && x.Issuer == issuer
                     && x.ProviderSub == providerSub,
                cancellationToken);

        return entity is null ? null : ToDto(entity);
    }

    public async Task<ExternalIdentityDto> CreateAsync(
        Guid tenantId,
        Guid ourSubject,
        string provider,
        string issuer,
        string providerSub,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var entity = new ExternalIdentityEntity
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            OurSubject = ourSubject,
            Provider = provider,
            Issuer = issuer,
            ProviderSub = providerSub,
            CreatedAt = now,
            Enabled = true,
            DisabledAt = null,
            DisabledReason = null,
        };

        _db.ExternalIdentities.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return ToDto(entity);
    }

    public async Task<bool> DisableAsync(
        Guid tenantId,
        string provider,
        string issuer,
        string providerSub,
        DateTimeOffset disabledAt,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        // Use raw SQL to avoid provider translation gaps while keeping the update atomic.
        var affected = await _db.Database.ExecuteSqlInterpolatedAsync(
            $@"UPDATE external_identities
SET Enabled = 0,
    DisabledAt = {disabledAt},
    DisabledReason = {reason}
WHERE TenantId = {tenantId}
  AND Provider = {provider}
  AND Issuer = {issuer}
  AND ProviderSub = {providerSub}
  AND Enabled = 1;",
            cancellationToken);

        return affected == 1;
    }

    private static ExternalIdentityDto ToDto(ExternalIdentityEntity entity)
        => new()
        {
            TenantId = entity.TenantId,
            OurSubject = entity.OurSubject,
            Provider = entity.Provider,
            Issuer = entity.Issuer,
            ProviderSub = entity.ProviderSub,
            Enabled = entity.Enabled,
            DisabledAt = entity.DisabledAt,
            DisabledReason = entity.DisabledReason,
        };
}
