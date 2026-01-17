namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Authorization.Evaluation;
using Microsoft.Extensions.Options;

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
        var catalog = new FakePermissionCatalogStore(new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["orders:read"] = "orders",
        });
        var entitlements = new FakeTenantEntitlementStore(enabled: false);

        var authzOptions = Options.Create(new SecurityAuthorizationOptions
        {
            PublicPermissionPrefixes = ["public:"],
        });

        IAuthorizationEvaluator evaluator = new EntitlementAuthorizationEvaluator(inner, catalog, entitlements, new OptionsMonitorShim<SecurityAuthorizationOptions>(authzOptions.Value));

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
        var catalog = new FakePermissionCatalogStore(new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["orders:read"] = "orders",
        });
        var entitlements = new FakeTenantEntitlementStore(enabled: true);

        var authzOptions = Options.Create(new SecurityAuthorizationOptions
        {
            PublicPermissionPrefixes = ["public:"],
        });

        IAuthorizationEvaluator evaluator = new EntitlementAuthorizationEvaluator(inner, catalog, entitlements, new OptionsMonitorShim<SecurityAuthorizationOptions>(authzOptions.Value));

        var decision = await evaluator.EvaluateAsync(new AuthorizationRequest(
            TenantId: tenantId,
            OurSubject: ourSubject,
            Resource: "orders",
            Action: "read"));

        Assert.True(decision.Allowed);
        Assert.Equal("permission_match", decision.Reason);
    }

    [Fact]
    public async Task EntitlementAuthorizationEvaluator_Denies_When_RequiredPrefix_Is_Public_In_Catalog()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var store = new FakeAuthorizationDataStore(
            permissions: ["orders:read"],
            scopes: [],
            roles: []);

        var inner = new SimpleRbacAuthorizationEvaluator(store);
        var catalog = new FakePermissionCatalogStore(new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            // Misconfigured: orders:* is supposed to be product-bound, but catalog says it's public.
            ["orders:read"] = null,
        });
        var entitlements = new FakeTenantEntitlementStore(enabled: true);

        var authzOptions = Options.Create(new SecurityAuthorizationOptions
        {
            PublicPermissionPrefixes = ["public:"],
            RequiredProductPrefixes = ["orders:"],
        });

        IAuthorizationEvaluator evaluator = new EntitlementAuthorizationEvaluator(inner, catalog, entitlements, new OptionsMonitorShim<SecurityAuthorizationOptions>(authzOptions.Value));

        var decision = await evaluator.EvaluateAsync(new AuthorizationRequest(
            TenantId: tenantId,
            OurSubject: ourSubject,
            Resource: "orders",
            Action: "read"));

        Assert.False(decision.Allowed);
        Assert.Equal("permission_catalog_violation", decision.Reason);
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
        private readonly IReadOnlyDictionary<string, string?> _productKeysByPermission;

        public FakePermissionCatalogStore(IReadOnlyDictionary<string, string?> productKeysByPermission)
        {
            _productKeysByPermission = productKeysByPermission;
        }

        public ValueTask<PermissionCatalogEntry?> TryGetPermissionAsync(string permissionKey, CancellationToken cancellationToken = default)
        {
            _ = cancellationToken;
            if (string.IsNullOrWhiteSpace(permissionKey))
            {
                return ValueTask.FromResult<PermissionCatalogEntry?>(null);
            }

            var key = permissionKey.Trim();
            if (_productKeysByPermission.TryGetValue(key, out var productKey))
            {
                return ValueTask.FromResult<PermissionCatalogEntry?>(new PermissionCatalogEntry(key, productKey));
            }

            return ValueTask.FromResult<PermissionCatalogEntry?>(null);
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

    private sealed class OptionsMonitorShim<T> : IOptionsMonitor<T>
        where T : class
    {
        public OptionsMonitorShim(T currentValue)
        {
            CurrentValue = currentValue;
        }

        public T CurrentValue { get; }

        public T Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
