namespace Birdsoft.Security.Authorization.Stores;

using Birdsoft.Security.Abstractions.Stores;

public sealed class NullPermissionCatalogStore : IPermissionCatalogStore
{
    public ValueTask<string?> GetProductKeyForPermissionAsync(string permissionKey, CancellationToken cancellationToken = default)
        => ValueTask.FromResult<string?>(null);
}
