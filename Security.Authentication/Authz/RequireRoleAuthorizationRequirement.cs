namespace Birdsoft.Security.Authentication.Authz;

using Microsoft.AspNetCore.Authorization;

public sealed record RequireRoleAuthorizationRequirement(string Role) : IAuthorizationRequirement;
