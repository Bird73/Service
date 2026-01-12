namespace Birdsoft.Security.Authorization.Tests.Unit;

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
}
