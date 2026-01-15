namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authorization.Evaluation;

public sealed class AuthorizationSkeletonTests
{
    [Fact]
    public async Task SimpleRbacAuthorizationEvaluator_Allows_When_Permission_Matches()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var store = new FakeAuthorizationDataStore(
            permissions: ["orders:read"],
            scopes: [],
            roles: []);

        IAuthorizationEvaluator evaluator = new SimpleRbacAuthorizationEvaluator(store);

        var decision = await evaluator.EvaluateAsync(new AuthorizationRequest(
            TenantId: tenantId,
            OurSubject: ourSubject,
            Resource: "orders",
            Action: "read"));

        Assert.True(decision.Allowed);
        Assert.Equal("permission_match", decision.Reason);
    }

    [Fact]
    public async Task EntitlementAuthorizationEvaluator_Denies_When_Product_Not_Entitled()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var store = new FakeAuthorizationDataStore(
            permissions: ["orders:read"],
            scopes: [],
            roles: []);

        var inner = new SimpleRbacAuthorizationEvaluator(store);
        var catalog = new FakePermissionCatalogStore(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["orders:read"] = "orders",
        });
        var entitlements = new FakeTenantEntitlementStore(enabled: false);

        IAuthorizationEvaluator evaluator = new EntitlementAuthorizationEvaluator(inner, catalog, entitlements);

        var decision = await evaluator.EvaluateAsync(new AuthorizationRequest(
            TenantId: tenantId,
            OurSubject: ourSubject,
            Resource: "orders",
            Action: "read"));

        Assert.False(decision.Allowed);
        Assert.Equal("entitlement_missing_or_disabled", decision.Reason);
    }

    [Fact]
    public async Task EntitlementAuthorizationEvaluator_Allows_When_Product_Entitled_And_Permission_Matches()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var store = new FakeAuthorizationDataStore(
            permissions: ["orders:read"],
            scopes: [],
            roles: []);

        var inner = new SimpleRbacAuthorizationEvaluator(store);
        var catalog = new FakePermissionCatalogStore(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["orders:read"] = "orders",
        });
        var entitlements = new FakeTenantEntitlementStore(enabled: true);

        IAuthorizationEvaluator evaluator = new EntitlementAuthorizationEvaluator(inner, catalog, entitlements);

        var decision = await evaluator.EvaluateAsync(new AuthorizationRequest(
            TenantId: tenantId,
            OurSubject: ourSubject,
            Resource: "orders",
            Action: "read"));

        Assert.True(decision.Allowed);
        Assert.Equal("permission_match", decision.Reason);
    }

    private sealed class FakeAuthorizationDataStore : IAuthorizationDataStore
    {
        private readonly HashSet<string> _permissions;
        private readonly HashSet<string> _scopes;
        private readonly HashSet<string> _roles;

        public FakeAuthorizationDataStore(IEnumerable<string> permissions, IEnumerable<string> scopes, IEnumerable<string> roles)
        {
            _permissions = new HashSet<string>(permissions, StringComparer.Ordinal);
            _scopes = new HashSet<string>(scopes, StringComparer.Ordinal);
            _roles = new HashSet<string>(roles, StringComparer.Ordinal);
        }

        public ValueTask<IReadOnlyList<string>> GetPermissionsAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
            => ValueTask.FromResult((IReadOnlyList<string>)_permissions.ToArray());

        public ValueTask<IReadOnlyList<string>> GetScopesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
            => ValueTask.FromResult((IReadOnlyList<string>)_scopes.ToArray());

        public ValueTask<IReadOnlyList<string>> GetRolesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
            => ValueTask.FromResult((IReadOnlyList<string>)_roles.ToArray());
    }

    private sealed class FakePermissionCatalogStore : IPermissionCatalogStore
    {
        private readonly IReadOnlyDictionary<string, string> _productKeysByPermission;

        public FakePermissionCatalogStore(IReadOnlyDictionary<string, string> productKeysByPermission)
        {
            _productKeysByPermission = productKeysByPermission;
        }

        public ValueTask<string?> GetProductKeyForPermissionAsync(string permissionKey, CancellationToken cancellationToken = default)
        {
            if (_productKeysByPermission.TryGetValue(permissionKey, out var productKey))
            {
                return ValueTask.FromResult<string?>(productKey);
            }
            return ValueTask.FromResult<string?>(null);
        }
    }

    private sealed class FakeTenantEntitlementStore : ITenantEntitlementStore
    {
        private readonly bool _enabled;

        public FakeTenantEntitlementStore(bool enabled)
        {
            _enabled = enabled;
        }

        public ValueTask<bool> IsProductEnabledAsync(Guid tenantId, string productKey, DateTimeOffset now, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(_enabled);
    }
}
