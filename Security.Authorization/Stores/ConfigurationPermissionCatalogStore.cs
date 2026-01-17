namespace Birdsoft.Security.Authorization.Stores;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Stores;
using Microsoft.Extensions.Options;
using System.Collections.Immutable;

/// <summary>
/// Fail-closed permission catalog for non-EF mode.
/// Unknown permissions resolve to null.
/// </summary>
public sealed class ConfigurationPermissionCatalogStore : IPermissionCatalogStore
{
    private readonly IOptionsMonitor<SecurityAuthorizationOptions> _options;
    private ImmutableDictionary<string, PermissionCatalogEntry> _cache = ImmutableDictionary<string, PermissionCatalogEntry>.Empty.WithComparers(StringComparer.Ordinal);

    public ConfigurationPermissionCatalogStore(IOptionsMonitor<SecurityAuthorizationOptions> options)
    {
        _options = options;
        RebuildCache(_options.CurrentValue);
        _options.OnChange(RebuildCache);
    }

    public ValueTask<PermissionCatalogEntry?> TryGetPermissionAsync(string permissionKey, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (string.IsNullOrWhiteSpace(permissionKey))
        {
            return ValueTask.FromResult<PermissionCatalogEntry?>(null);
        }

        return ValueTask.FromResult(_cache.TryGetValue(permissionKey, out var entry) ? entry : null);
    }

    private void RebuildCache(SecurityAuthorizationOptions options)
    {
        var builder = ImmutableDictionary.CreateBuilder<string, PermissionCatalogEntry>(StringComparer.Ordinal);

        if (options.PermissionCatalog is { Length: > 0 })
        {
            foreach (var e in options.PermissionCatalog)
            {
                if (string.IsNullOrWhiteSpace(e.PermissionKey))
                {
                    continue;
                }

                var permKey = e.PermissionKey.Trim();
                var productKey = string.IsNullOrWhiteSpace(e.ProductKey) ? null : e.ProductKey.Trim();
                builder[permKey] = new PermissionCatalogEntry(permKey, productKey);
            }
        }

        _cache = builder.ToImmutable();
    }
}
