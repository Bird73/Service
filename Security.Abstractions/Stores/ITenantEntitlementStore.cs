namespace Birdsoft.Security.Abstractions.Stores;

public interface ITenantEntitlementStore
{
    /// <summary>
    /// True when the tenant currently has an enabled entitlement for the given product.
    /// </summary>
    ValueTask<bool> IsProductEnabledAsync(Guid tenantId, string productKey, DateTimeOffset now, CancellationToken cancellationToken = default);
}
