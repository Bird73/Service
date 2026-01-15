namespace Birdsoft.Security.Authorization.Stores;

using Birdsoft.Security.Abstractions.Stores;

public sealed class AllowAllTenantEntitlementStore : ITenantEntitlementStore
{
    public ValueTask<bool> IsProductEnabledAsync(Guid tenantId, string productKey, DateTimeOffset now, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(true);
}
