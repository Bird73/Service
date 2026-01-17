namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Stores;
using Microsoft.EntityFrameworkCore;

public sealed class EfTenantEntitlementStore : ITenantEntitlementStore
{
    private readonly SecurityDbContext _db;

    public EfTenantEntitlementStore(SecurityDbContext db)
    {
        _db = db;
    }

    public async ValueTask<bool> IsProductEnabledAsync(Guid tenantId, string productKey, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (tenantId == Guid.Empty || string.IsNullOrWhiteSpace(productKey))
        {
            return false;
        }

        // Require product exists + enabled and tenant entitlement exists + enabled.
        // Note: SQLite has limitations translating DateTimeOffset comparisons; apply the time-window check in-memory.
        var row = await (
            from tp in _db.TenantProducts.AsNoTracking()
            join t in _db.Tenants.AsNoTracking() on tp.TenantId equals t.TenantId
            join p in _db.Products.AsNoTracking() on tp.ProductKey equals p.ProductKey
            where tp.TenantId == tenantId
                && tp.ProductKey == productKey
                && tp.Status == (int)TenantProductStatus.Enabled
                && t.Status == (int)TenantStatus.Active
                && p.Status == (int)ProductStatus.Enabled
            select new
            {
                tp.StartAt,
                tp.EndAt,
            }
        ).FirstOrDefaultAsync(cancellationToken);

        return row is not null
            && row.StartAt <= now
            && (row.EndAt is null || row.EndAt > now);
    }
}
