namespace Birdsoft.Security.Authentication.Authz;

using Microsoft.AspNetCore.Authorization;

public sealed class RequireRoleAuthorizationHandler : AuthorizationHandler<RequireRoleAuthorizationRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RequireRoleAuthorizationRequirement requirement)
    {
        if (ClaimHelpers.HasRole(context.User, requirement.Role))
        {
            context.Succeed(requirement);
        }
        else
        {
            context.Fail(new AuthorizationFailureReason(this, ApiAuthorizationErrorCodes.Forbidden));
        }

        return Task.CompletedTask;
    }
}
