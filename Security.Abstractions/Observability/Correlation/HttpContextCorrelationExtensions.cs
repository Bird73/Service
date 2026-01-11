namespace Birdsoft.Security.Abstractions.Observability.Correlation;

using System.Diagnostics;
using Microsoft.AspNetCore.Http;

public static class HttpContextCorrelationExtensions
{
    public static string? GetCorrelationId(this HttpContext http)
        => http.Items.TryGetValue(CorrelationConstants.CorrelationItemKey, out var v) ? v as string : null;

    public static string? GetTraceId(this HttpContext http)
        => Activity.Current?.TraceId.ToString();
}
