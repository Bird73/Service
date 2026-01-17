namespace Birdsoft.Security.Abstractions.Stores;

public sealed record PermissionCatalogEntry(
    string PermissionKey,
    string? ProductKey);

public interface IPermissionCatalogStore
{
    /// <summary>
    /// Returns a catalog entry for the permission key (e.g. "orders:read").
    ///
    /// - Return null when the permission is unknown.
    /// - Return entry with ProductKey=null when the permission is known and public (not associated with a product).
    /// </summary>
    ValueTask<PermissionCatalogEntry?> TryGetPermissionAsync(string permissionKey, CancellationToken cancellationToken = default);
}
