namespace Birdsoft.Security.Authorization.Evaluation;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authorization.Stores;
using Microsoft.Extensions.Options;

public sealed class EntitlementAuthorizationEvaluator : IAuthorizationEvaluator
{
    private readonly IAuthorizationEvaluator _inner;
    private readonly IPermissionCatalogStore _permissionCatalog;
    private readonly ITenantEntitlementStore _entitlements;
    private readonly IOptionsMonitor<SecurityAuthorizationOptions> _authzOptions;

    public EntitlementAuthorizationEvaluator(
        IAuthorizationEvaluator inner,
        IPermissionCatalogStore permissionCatalog,
        ITenantEntitlementStore entitlements,
        IOptionsMonitor<SecurityAuthorizationOptions> authzOptions)
    {
        _inner = inner;
        _permissionCatalog = permissionCatalog;
        _entitlements = entitlements;
        _authzOptions = authzOptions;

        ThrowIfDangerousStores(permissionCatalog, entitlements, _authzOptions.CurrentValue);
    }

    public async ValueTask<AuthorizationDecision> EvaluateAsync(AuthorizationRequest request, CancellationToken cancellationToken = default)
    {
        var requiredPermission = $"{request.Resource}:{request.Action}";

        // Re-check on each call in case config hot-reloads.
        ThrowIfDangerousStores(_permissionCatalog, _entitlements, _authzOptions.CurrentValue);

        var entry = await _permissionCatalog.TryGetPermissionAsync(requiredPermission, cancellationToken);
        if (entry is null)
        {
            // Unknown permission -> deny (do not allow implicit/"admin" escalation).
            return AuthorizationDecision.Deny("unknown_permission");
        }

        // Public permission (known but not associated with a product) -> bypass entitlement gating.
        if (string.IsNullOrWhiteSpace(entry.ProductKey))
        {
            var opts = _authzOptions.CurrentValue;

            // Catalog integrity: some permission prefixes MUST be product-bound.
            if (opts.RequiredProductPrefixes.Any(p => !string.IsNullOrWhiteSpace(p) && requiredPermission.StartsWith(p, StringComparison.Ordinal)))
            {
                return AuthorizationDecision.Deny("permission_catalog_violation");
            }

            // Public permission is allowed only when explicitly configured.
            var isPublicAllowed = opts.PublicPermissions.Any(p => string.Equals(p, requiredPermission, StringComparison.Ordinal))
                || opts.PublicPermissionPrefixes.Any(p => !string.IsNullOrWhiteSpace(p) && requiredPermission.StartsWith(p, StringComparison.Ordinal));

            if (!isPublicAllowed)
            {
                return AuthorizationDecision.Deny("permission_catalog_violation");
            }

            return await _inner.EvaluateAsync(request, cancellationToken);
        }

        var productKey = entry.ProductKey;

        var now = DateTimeOffset.UtcNow;
        var enabled = await _entitlements.IsProductEnabledAsync(request.TenantId, productKey, now, cancellationToken);
        if (!enabled)
        {
            return AuthorizationDecision.Deny("entitlement_missing_or_disabled");
        }

        return await _inner.EvaluateAsync(request, cancellationToken);
    }

    private static void ThrowIfDangerousStores(
        IPermissionCatalogStore permissionCatalog,
        ITenantEntitlementStore entitlements,
        SecurityAuthorizationOptions opts)
    {
        if (opts.UnsafeDevMode)
        {
            return;
        }

        // Guardrails: if an allow-all store is accidentally injected, fail-fast.
        if (permissionCatalog is NullPermissionCatalogStore)
        {
            throw new InvalidOperationException("Unsafe authorization configuration: NullPermissionCatalogStore is not allowed unless Security:Authorization:UnsafeDevMode=true.");
        }

        if (entitlements is AllowAllTenantEntitlementStore)
        {
            throw new InvalidOperationException("Unsafe authorization configuration: AllowAllTenantEntitlementStore is not allowed unless Security:Authorization:UnsafeDevMode=true.");
        }
    }
}
