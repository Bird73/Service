namespace Birdsoft.Security.Authentication.Authz;

using Birdsoft.Security.Abstractions.Constants;
using System.Security.Claims;

internal static class ClaimHelpers
{
    public static bool HasScope(ClaimsPrincipal? user, string requiredScope)
    {
        if (user?.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        var scope = user.FindFirst(SecurityClaimTypes.Scope)?.Value;
        if (!string.IsNullOrWhiteSpace(scope))
        {
            var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (scopes.Any(s => string.Equals(s, requiredScope, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        var multi = user.FindAll(SecurityClaimTypes.Scopes).Select(c => c.Value);
        return multi.Any(s => string.Equals(s, requiredScope, StringComparison.OrdinalIgnoreCase));
    }

    public static bool HasRole(ClaimsPrincipal? user, string requiredRole)
    {
        if (user?.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        var roles = user.FindAll(SecurityClaimTypes.Roles).Select(c => c.Value)
            .Concat(user.FindAll(SecurityClaimTypes.Role).Select(c => c.Value));

        return roles.Any(r => string.Equals(r, requiredRole, StringComparison.OrdinalIgnoreCase));
    }
}
