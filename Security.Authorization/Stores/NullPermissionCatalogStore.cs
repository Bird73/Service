namespace Birdsoft.Security.Authorization.Stores;

using Birdsoft.Security.Abstractions.Stores;

public sealed class NullPermissionCatalogStore : IPermissionCatalogStore
{
    public ValueTask<PermissionCatalogEntry?> TryGetPermissionAsync(string permissionKey, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;

        if (string.IsNullOrWhiteSpace(permissionKey))
        {
            return ValueTask.FromResult<PermissionCatalogEntry?>(null);
        }

        // Dev/in-memory mode: assume every permission is known and public.
        // Real hosts should use EF-backed catalog so unknown permissions are denied.
        var key = permissionKey.Trim();
        return ValueTask.FromResult<PermissionCatalogEntry?>(new PermissionCatalogEntry(key, ProductKey: null));
    }
}
