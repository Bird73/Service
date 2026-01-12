namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Authorization.Claims;
using System.Security.Claims;

public sealed class JwtClaimsProjectionTests
{
    [Fact]
    public void GetRoles_Merges_Roles_And_Role_And_Dedupes_And_Trims()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(SecurityClaimTypes.Roles, "admin"),
                new Claim(SecurityClaimTypes.Roles, " admin "),
                new Claim(SecurityClaimTypes.Role, "user"),
                new Claim(SecurityClaimTypes.Role, ""),
            ],
            authenticationType: "test"));

        var roles = JwtClaimsProjection.GetRoles(principal);

        Assert.Contains("admin", roles);
        Assert.Contains("user", roles);
        Assert.Equal(2, roles.Count);
    }

    [Fact]
    public void GetScopes_Merges_Scopes_Array_And_SpaceDelimited_Scope_And_Dedupes()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(SecurityClaimTypes.Scopes, "read"),
                new Claim(SecurityClaimTypes.Scopes, "write"),
                new Claim(SecurityClaimTypes.Scope, "read delete"),
            ],
            authenticationType: "test"));

        var scopes = JwtClaimsProjection.GetScopes(principal);

        Assert.Contains("read", scopes);
        Assert.Contains("write", scopes);
        Assert.Contains("delete", scopes);
        Assert.Equal(3, scopes.Count);
    }

    [Fact]
    public void GetPermissions_Dedupes_Trims_And_Ignores_Empty()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(SecurityClaimTypes.Permissions, "read"),
                new Claim(SecurityClaimTypes.Permissions, " read "),
                new Claim(SecurityClaimTypes.Permissions, ""),
                new Claim(SecurityClaimTypes.Permissions, "write"),
            ],
            authenticationType: "test"));

        var perms = JwtClaimsProjection.GetPermissions(principal);

        Assert.Contains("read", perms);
        Assert.Contains("write", perms);
        Assert.Equal(2, perms.Count);
    }
}
