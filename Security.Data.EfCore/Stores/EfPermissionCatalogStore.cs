namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Stores;
using Microsoft.EntityFrameworkCore;

public sealed class EfPermissionCatalogStore : IPermissionCatalogStore
{
    private readonly SecurityDbContext _db;

    public EfPermissionCatalogStore(SecurityDbContext db)
    {
        _db = db;
    }

    public async ValueTask<PermissionCatalogEntry?> TryGetPermissionAsync(string permissionKey, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(permissionKey))
        {
            return null;
        }

        var key = permissionKey.Trim();

        var row = await _db.Permissions
            .AsNoTracking()
            .Where(p => p.PermKey == key)
            .Select(p => new { p.PermKey, p.ProductKey })
            .FirstOrDefaultAsync(cancellationToken);

        if (row is null)
        {
            return null;
        }

        return new PermissionCatalogEntry(row.PermKey, row.ProductKey);
    }
}
