namespace Birdsoft.Security.Abstractions.RateLimiting;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Audit;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Observability.Correlation;
using Microsoft.AspNetCore.Http;

public sealed class RateLimitEndpointFilter(string policyName, AuthEventType? eventType = null) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var gate = http.RequestServices.GetService(typeof(IRateLimiterGate)) as IRateLimiterGate;
        if (gate is null)
        {
            return await next(context);
        }

        var decision = await gate.TryAcquireAsync(http, policyName, http.RequestAborted);
        if (decision.Allowed)
        {
            return await next(context);
        }

        if (decision.RetryAfterSeconds is int ra)
        {
            http.Response.Headers.RetryAfter = ra.ToString();
        }

        if (eventType is not null)
        {
            var writer = http.RequestServices.GetService(typeof(IAuditEventWriter)) as IAuditEventWriter;
            if (writer is not null)
            {
                Guid? tenantId = null;
                if (http.Items.TryGetValue("Birdsoft.Security.TenantContext", out var tenantObj)
                    && tenantObj is Birdsoft.Security.Abstractions.Tenancy.TenantContext ctx)
                {
                    tenantId = ctx.TenantId;
                }

                await writer.WriteAsync(new AuthEvent
                {
                    Id = Guid.NewGuid(),
                    OccurredAt = DateTimeOffset.UtcNow,
                    TenantId = tenantId,
                    Type = AuthEventType.SecurityDefense,
                    Outcome = "block",
                    Code = AuthErrorCodes.RateLimited,
                    CorrelationId = http.GetCorrelationId(),
                    TraceId = http.GetTraceId(),
                    Ip = http.Connection.RemoteIpAddress?.ToString(),
                    UserAgent = http.Request.Headers.UserAgent.ToString(),
                }, http.RequestAborted);
            }
        }

        return Results.Json(ApiResponse<object>.Fail(AuthErrorCodes.RateLimited), statusCode: StatusCodes.Status429TooManyRequests);
    }
}
