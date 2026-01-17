namespace Birdsoft.Security.Authorization.Stores;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Stores;
using Microsoft.Extensions.Options;
using System.Collections.Immutable;

/// <summary>
/// Fail-closed entitlement store for non-EF mode.
/// If no entitlement entry exists, product is treated as disabled.
/// </summary>
public sealed class ConfigurationTenantEntitlementStore : ITenantEntitlementStore
{
    private sealed record Entry(bool Enabled, DateTimeOffset? StartAt, DateTimeOffset? EndAt);

    private readonly IOptionsMonitor<SecurityAuthorizationOptions> _options;
    private ImmutableDictionary<(Guid TenantId, string ProductKey), Entry> _cache = ImmutableDictionary<(Guid, string), Entry>.Empty;

    public ConfigurationTenantEntitlementStore(IOptionsMonitor<SecurityAuthorizationOptions> options)
    {
        _options = options;
        RebuildCache(_options.CurrentValue);
        _options.OnChange(RebuildCache);
    }

    public ValueTask<bool> IsProductEnabledAsync(Guid tenantId, string productKey, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (tenantId == Guid.Empty || string.IsNullOrWhiteSpace(productKey))
        {
            return ValueTask.FromResult(false);
        }

        var key = (tenantId, productKey.Trim());
        if (!_cache.TryGetValue(key, out var entry))
        {
            return ValueTask.FromResult(false);
        }

        if (!entry.Enabled)
        {
            return ValueTask.FromResult(false);
        }

        if (entry.StartAt.HasValue && now < entry.StartAt.Value)
        {
            return ValueTask.FromResult(false);
        }

        if (entry.EndAt.HasValue && now > entry.EndAt.Value)
        {
            return ValueTask.FromResult(false);
        }

        return ValueTask.FromResult(true);
    }

    private void RebuildCache(SecurityAuthorizationOptions options)
    {
        var builder = ImmutableDictionary.CreateBuilder<(Guid, string), Entry>();

        if (options.TenantEntitlements is { Length: > 0 })
        {
            foreach (var e in options.TenantEntitlements)
            {
                if (e.TenantId == Guid.Empty || string.IsNullOrWhiteSpace(e.ProductKey))
                {
                    continue;
                }

                builder[(e.TenantId, e.ProductKey.Trim())] = new Entry(e.Enabled, e.StartAt, e.EndAt);
            }
        }

        _cache = builder.ToImmutable();
    }
}
