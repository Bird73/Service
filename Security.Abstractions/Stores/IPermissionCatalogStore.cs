namespace Birdsoft.Security.Abstractions.Stores;

public interface IPermissionCatalogStore
{
    /// <summary>
    /// Returns the ProductKey associated with a permission key (e.g. "orders:read").
    /// Return null when the permission is unknown or not associated with a product.
    /// </summary>
    ValueTask<string?> GetProductKeyForPermissionAsync(string permissionKey, CancellationToken cancellationToken = default);
}
