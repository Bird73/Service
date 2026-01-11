namespace Birdsoft.Security.Abstractions.Observability.Correlation;

using System.Diagnostics;
using Microsoft.AspNetCore.Http;

public static class CorrelationConstants
{
    public const string CorrelationHeaderName = "X-Correlation-Id";
    public const string CorrelationItemKey = "Birdsoft.Security.CorrelationId";
}

public sealed class CorrelationIdMiddleware : IMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var correlationId = TryGetIncomingCorrelationId(context) ?? Guid.NewGuid().ToString("N");
        context.Items[CorrelationConstants.CorrelationItemKey] = correlationId;

        context.Response.OnStarting(() =>
        {
            context.Response.Headers[CorrelationConstants.CorrelationHeaderName] = correlationId;
            return Task.CompletedTask;
        });

        // Ensure Activity exists for TraceId.
        Activity.Current ??= new Activity("Birdsoft.Security.Request").Start();

        await next(context);
    }

    private static string? TryGetIncomingCorrelationId(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue(CorrelationConstants.CorrelationHeaderName, out var value))
        {
            return null;
        }

        var raw = value.ToString().Trim();
        return string.IsNullOrWhiteSpace(raw) ? null : raw;
    }
}
