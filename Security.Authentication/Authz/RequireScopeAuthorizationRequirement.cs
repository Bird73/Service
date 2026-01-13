namespace Birdsoft.Security.Authentication.Authz;

using Microsoft.AspNetCore.Authorization;

public sealed record RequireScopeAuthorizationRequirement(string Scope) : IAuthorizationRequirement;
