namespace Birdsoft.Security.Authentication.Authz;

using Microsoft.AspNetCore.Authorization;

public sealed class RequireScopeAuthorizationHandler : AuthorizationHandler<RequireScopeAuthorizationRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RequireScopeAuthorizationRequirement requirement)
    {
        if (ClaimHelpers.HasScope(context.User, requirement.Scope))
        {
            context.Succeed(requirement);
        }
        else
        {
            context.Fail(new AuthorizationFailureReason(this, ApiAuthorizationErrorCodes.InsufficientScope));
        }

        return Task.CompletedTask;
    }
}
