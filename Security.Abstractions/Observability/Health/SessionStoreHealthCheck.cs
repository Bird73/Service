namespace Birdsoft.Security.Abstractions.Observability.Health;

using Birdsoft.Security.Abstractions.Stores;
using Microsoft.Extensions.Diagnostics.HealthChecks;

public sealed class SessionStoreHealthCheck : IHealthCheck
{
    private readonly ISessionStore _sessions;

    public SessionStoreHealthCheck(ISessionStore sessions) => _sessions = sessions;

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        _ = context;

        try
        {
            // The goal is to ensure the store is reachable and does not throw.
            var ok = await _sessions.IsSessionActiveAsync(Guid.NewGuid(), Guid.NewGuid(), cancellationToken);
            _ = ok;
            return HealthCheckResult.Healthy();
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Session store failure", ex);
        }
    }
}
