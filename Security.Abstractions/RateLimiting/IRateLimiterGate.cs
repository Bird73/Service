namespace Birdsoft.Security.Abstractions.RateLimiting;

using Microsoft.AspNetCore.Http;

public interface IRateLimiterGate
{
    ValueTask<RateLimitDecision> TryAcquireAsync(HttpContext http, string policyName, CancellationToken cancellationToken = default);
}
