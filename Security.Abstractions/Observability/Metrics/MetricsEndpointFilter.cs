namespace Birdsoft.Security.Abstractions.Observability.Metrics;

using System.Diagnostics;
using Microsoft.AspNetCore.Http;

public sealed class MetricsEndpointFilter(string operation) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var result = await next(context);
            SecurityMetrics.Increment($"{operation}_requests_total");
            return result;
        }
        catch
        {
            SecurityMetrics.Increment($"{operation}_exceptions_total");
            throw;
        }
        finally
        {
            sw.Stop();
            SecurityMetrics.ObserveLatencyMs($"{operation}_latency", sw.Elapsed.TotalMilliseconds);
        }
    }
}
