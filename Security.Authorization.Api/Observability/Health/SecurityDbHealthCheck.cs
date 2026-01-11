namespace Birdsoft.Security.Authorization.Api.Observability.Health;

using Birdsoft.Security.Data.EfCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

public sealed class SecurityDbHealthCheck(SecurityDbContext db) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        _ = context;

        try
        {
            var ok = await db.Database.CanConnectAsync(cancellationToken);
            return ok ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy("Cannot connect to database");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database check failed", ex);
        }
    }
}
