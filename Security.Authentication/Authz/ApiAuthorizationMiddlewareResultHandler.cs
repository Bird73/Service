namespace Birdsoft.Security.Authentication.Authz;

using Birdsoft.Security.Abstractions.Contracts.Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

public sealed class ApiAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _fallback = new();

    public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Succeeded)
        {
            await _fallback.HandleAsync(next, context, policy, authorizeResult);
            return;
        }

        if (authorizeResult.Challenged)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";

            var hasBearer = context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
            var code = hasBearer ? ApiAuthorizationErrorCodes.InvalidToken : ApiAuthorizationErrorCodes.MissingBearerToken;

            await context.Response.WriteAsJsonAsync(ApiResponse<object>.Fail(code));
            return;
        }

        if (authorizeResult.Forbidden)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";

            var code = DetermineForbiddenCode(authorizeResult.AuthorizationFailure);
            await context.Response.WriteAsJsonAsync(ApiResponse<object>.Fail(code));
            return;
        }

        await _fallback.HandleAsync(next, context, policy, authorizeResult);
    }

    private static string DetermineForbiddenCode(AuthorizationFailure? failure)
    {
        if (failure is null)
        {
            return ApiAuthorizationErrorCodes.Forbidden;
        }

        if (failure.FailedRequirements.OfType<RequireScopeAuthorizationRequirement>().Any())
        {
            return ApiAuthorizationErrorCodes.InsufficientScope;
        }

        if (failure.FailedRequirements.OfType<RequireRoleAuthorizationRequirement>().Any())
        {
            return ApiAuthorizationErrorCodes.Forbidden;
        }

        // Fallback to any explicit failure reasons.
        var reason = failure.FailureReasons.FirstOrDefault()?.Message;
        if (string.Equals(reason, ApiAuthorizationErrorCodes.InsufficientScope, StringComparison.Ordinal))
        {
            return ApiAuthorizationErrorCodes.InsufficientScope;
        }

        return ApiAuthorizationErrorCodes.Forbidden;
    }
}
