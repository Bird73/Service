namespace Birdsoft.Security.Data.EfCore.Repositories;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfTenantRepository : ITenantRepository
{
    private readonly SecurityDbContext _db;

    public EfTenantRepository(SecurityDbContext db) => _db = db;

    public async Task<TenantDto?> FindAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        var entity = await _db.Tenants.AsNoTracking()
            .FirstOrDefaultAsync(x => x.TenantId == tenantId, cancellationToken);

        return entity is null
            ? null
            : new TenantDto
            {
                TenantId = entity.TenantId,
                Name = entity.Name,
                Status = (TenantStatus)entity.Status,
                TokenVersion = entity.TokenVersion,
                CreatedAt = entity.CreatedAt,
            };
    }

    public async Task<TenantDto> CreateAsync(Guid tenantId, string name, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var entity = new TenantEntity
        {
            TenantId = tenantId,
            Name = name,
            Status = (int)TenantStatus.Active,
            TokenVersion = 0,
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.Tenants.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return new TenantDto
        {
            TenantId = entity.TenantId,
            Name = entity.Name,
            Status = (TenantStatus)entity.Status,
            TokenVersion = entity.TokenVersion,
            CreatedAt = entity.CreatedAt,
        };
    }

    public async Task<int> IncrementTokenVersionAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        return await _db.Tenants
            .Where(x => x.TenantId == tenantId)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.TokenVersion, x => x.TokenVersion + 1)
                .SetProperty(x => x.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);
    }

    public async Task<int> UpdateStatusAsync(Guid tenantId, TenantStatus status, CancellationToken cancellationToken = default)
    {
        return await _db.Tenants
            .Where(x => x.TenantId == tenantId)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.Status, (int)status)
                .SetProperty(x => x.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);
    }
}
