namespace Birdsoft.Security.Authentication.Authz;

public static class TestAuthorizationPolicies
{
    public const string ScopeRead = "TestScopeRead";
    public const string AdminRole = "TestAdminRole";

    public const string RequiredScopeRead = "scope:read";
    public const string RequiredRoleAdmin = "Admin";
}
