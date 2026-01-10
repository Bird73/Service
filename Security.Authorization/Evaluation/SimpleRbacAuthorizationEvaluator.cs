namespace Birdsoft.Security.Authorization.Evaluation;

using Birdsoft.Security.Abstractions.Stores;

/// <summary>
/// 最小 RBAC / scope-based evaluator（骨架）。
/// </summary>
public sealed class SimpleRbacAuthorizationEvaluator : IAuthorizationEvaluator
{
    private readonly IAuthorizationDataStore _store;

    public SimpleRbacAuthorizationEvaluator(IAuthorizationDataStore store)
    {
        _store = store;
    }

    public async ValueTask<AuthorizationDecision> EvaluateAsync(AuthorizationRequest request, CancellationToken cancellationToken = default)
    {
        var scopes = await _store.GetScopesAsync(request.TenantId, request.OurSubject, cancellationToken);
        var required = $"{request.Resource}:{request.Action}";

        if (scopes.Contains(required, StringComparer.Ordinal))
        {
            return AuthorizationDecision.Allow("scope_match");
        }

        var roles = await _store.GetRolesAsync(request.TenantId, request.OurSubject, cancellationToken);
        if (roles.Contains("admin", StringComparer.Ordinal))
        {
            return AuthorizationDecision.Allow("admin_role");
        }

        return AuthorizationDecision.Deny("no_matching_role_or_scope");
    }
}
