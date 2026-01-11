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
        };

        _db.ExternalIdentities.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return ToDto(entity);
    }

    private static ExternalIdentityDto ToDto(ExternalIdentityEntity entity)
        => new()
        {
            TenantId = entity.TenantId,
            OurSubject = entity.OurSubject,
            Provider = entity.Provider,
            Issuer = entity.Issuer,
            ProviderSub = entity.ProviderSub,
        };
}
