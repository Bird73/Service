namespace Birdsoft.Security.Authentication.Observability.Logging;

using Birdsoft.Infrastructure.Logging.Abstractions;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Observability.Correlation;
using Microsoft.AspNetCore.Http;
using System.Net;

public sealed class AuthErrorLoggingMiddleware
{
    private readonly RequestDelegate _next;

    public AuthErrorLoggingMiddleware(RequestDelegate next)
        => _next = next ?? throw new ArgumentNullException(nameof(next));

    public async Task Invoke(HttpContext http, IAppLogger<AuthErrorLoggingMiddleware> errorLog)
    {
        try
        {
            await _next(http);
        }
        catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
        {
            // Client aborted request; do not treat as server error.
            throw;
        }
        catch (Exception ex)
        {
            // Write error log (jsonl) via Birdsoft.Infrastructure.Logging.
            var traceId = http.GetTraceId();
            var correlationId = http.GetCorrelationId();
            var ip = http.Connection.RemoteIpAddress?.ToString();
            var tenantHeader = http.Request.Headers.TryGetValue("X-Tenant-Id", out var h) ? h.ToString() : null;

            try
            {
                errorLog.Log(
                    LogLevel.Error,
                    ex,
                    "Unhandled exception. method={Method} path={Path} query={Query} status={Status} traceId={TraceId} correlationId={CorrelationId} tenantHeader={TenantHeader} ip={Ip}",
                    http.Request.Method,
                    http.Request.Path.ToString(),
                    http.Request.QueryString.ToString(),
                    http.Response.StatusCode,
                    traceId,
                    correlationId,
                    tenantHeader,
                    ip);
            }
            catch
            {
                // Logging must never break the request pipeline.
            }

            if (http.Response.HasStarted)
            {
                throw;
            }

            http.Response.Clear();
            http.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
            http.Response.ContentType = "application/json";

            await http.Response.WriteAsJsonAsync(ApiResponse<object>.Fail(AuthErrorCodes.InternalError));
        }
    }
}
