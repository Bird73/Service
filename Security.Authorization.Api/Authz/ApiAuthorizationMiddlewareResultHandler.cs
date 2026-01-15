namespace Birdsoft.Security.Authorization.Api.Authz;

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

            // Authorization API policies are implemented via custom assertions (no scope/role requirements),
            // so we map tenant admin surface denies to insufficient_scope.
            var code = DetermineForbiddenCode(context);
            await context.Response.WriteAsJsonAsync(ApiResponse<object>.Fail(code));
            return;
        }

        await _fallback.HandleAsync(next, context, policy, authorizeResult);
    }

    private static string DetermineForbiddenCode(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        if (path.StartsWith("/api/v1/tenant", StringComparison.OrdinalIgnoreCase))
        {
            return ApiAuthorizationErrorCodes.InsufficientScope;
        }

        return ApiAuthorizationErrorCodes.Forbidden;
    }
}
