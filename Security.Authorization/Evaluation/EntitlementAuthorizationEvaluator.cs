namespace Birdsoft.Security.Authorization.Evaluation;

using Birdsoft.Security.Abstractions.Stores;

public sealed class EntitlementAuthorizationEvaluator : IAuthorizationEvaluator
{
    private readonly IAuthorizationEvaluator _inner;
    private readonly IPermissionCatalogStore _permissionCatalog;
    private readonly ITenantEntitlementStore _entitlements;

    public EntitlementAuthorizationEvaluator(
        IAuthorizationEvaluator inner,
        IPermissionCatalogStore permissionCatalog,
        ITenantEntitlementStore entitlements)
    {
        _inner = inner;
        _permissionCatalog = permissionCatalog;
        _entitlements = entitlements;
    }

    public async ValueTask<AuthorizationDecision> EvaluateAsync(AuthorizationRequest request, CancellationToken cancellationToken = default)
    {
        var requiredPermission = $"{request.Resource}:{request.Action}";

        var productKey = await _permissionCatalog.GetProductKeyForPermissionAsync(requiredPermission, cancellationToken);
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return await _inner.EvaluateAsync(request, cancellationToken);
        }

        var now = DateTimeOffset.UtcNow;
        var enabled = await _entitlements.IsProductEnabledAsync(request.TenantId, productKey, now, cancellationToken);
        if (!enabled)
        {
            return AuthorizationDecision.Deny("entitlement_missing_or_disabled");
        }

        return await _inner.EvaluateAsync(request, cancellationToken);
    }
}
