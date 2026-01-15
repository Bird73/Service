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

    public async ValueTask<string?> GetProductKeyForPermissionAsync(string permissionKey, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(permissionKey))
        {
            return null;
        }

        return await _db.Permissions
            .AsNoTracking()
            .Where(p => p.PermKey == permissionKey)
            .Select(p => p.ProductKey)
            .FirstOrDefaultAsync(cancellationToken);
    }
}
