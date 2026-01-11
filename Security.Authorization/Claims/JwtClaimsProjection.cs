namespace Birdsoft.Security.Authorization.Claims;

using Birdsoft.Security.Abstractions.Constants;
using System.Security.Claims;

public static class JwtClaimsProjection
{
    public static IReadOnlyList<string> GetRoles(ClaimsPrincipal principal)
    {
        var roles = principal.FindAll(SecurityClaimTypes.Roles)
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToList();

        // Compat: single-value role
        roles.AddRange(principal.FindAll(SecurityClaimTypes.Role)
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v)));

        return roles.Select(v => v.Trim())
            .Where(v => v.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    public static IReadOnlyList<string> GetScopes(ClaimsPrincipal principal)
    {
        var scopes = principal.FindAll(SecurityClaimTypes.Scopes)
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToList();

        // Compat: OAuth scope = "a b c"
        var scopeClaim = principal.FindFirst(SecurityClaimTypes.Scope)?.Value;
        if (!string.IsNullOrWhiteSpace(scopeClaim))
        {
            scopes.AddRange(scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        return scopes.Select(v => v.Trim())
            .Where(v => v.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    public static IReadOnlyList<string> GetPermissions(ClaimsPrincipal principal)
    {
        var permissions = principal.FindAll(SecurityClaimTypes.Permissions)
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v.Trim())
            .Where(v => v.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return permissions;
    }
}
