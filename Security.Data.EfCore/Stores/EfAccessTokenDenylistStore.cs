namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfAccessTokenDenylistStore : IAccessTokenDenylistStore
{
    private readonly SecurityDbContext _db;

    public EfAccessTokenDenylistStore(SecurityDbContext db) => _db = db;

    public async Task AddAsync(Guid tenantId, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        var exists = await _db.AccessTokenDenylist.AsNoTracking()
            .AnyAsync(x => x.TenantId == tenantId && x.Jti == jti, cancellationToken);

        if (exists)
        {
            return;
        }

        _db.AccessTokenDenylist.Add(new AccessTokenDenylistEntity
        {
            TenantId = tenantId,
            Jti = jti,
            ExpiresAt = expiresAt,
            CreatedAt = DateTimeOffset.UtcNow,
        });

        await _db.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> ContainsAsync(Guid tenantId, string jti, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var entity = await _db.AccessTokenDenylist.AsNoTracking()
            .SingleOrDefaultAsync(x => x.TenantId == tenantId && x.Jti == jti, cancellationToken);

        return entity is not null && entity.ExpiresAt > now;
    }
}
