namespace Birdsoft.Security.Authorization.Api.Observability.Health;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Authorization.Api.Auth;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

public sealed class JwtValidationKeyHealthCheck(IJwtKeyProvider keys, IOptionsMonitor<JwtOptions> jwtOptions) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        _ = context;
        _ = cancellationToken;

        var opts = jwtOptions.CurrentValue;
        if (opts.KeyRing?.Keys is { Length: > 0 })
        {
            var active = opts.KeyRing.Keys.Any(k => k.Status == JwtKeyStatus.Active);
            if (!active)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("No active JWT signing key in KeyRing"));
            }
        }

        try
        {
            var alg = keys.Algorithm;
            if (alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                var rsa = keys.GetRsaPublicKey();
                if (rsa is null)
                {
                    return Task.FromResult(HealthCheckResult.Unhealthy("Missing RSA public key"));
                }
            }
            else
            {
                var sym = keys.GetSymmetricKeyBytes();
                if (sym is null || sym.Length == 0)
                {
                    return Task.FromResult(HealthCheckResult.Unhealthy("Missing symmetric key"));
                }
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("JWT key provider failure", ex));
        }

        return Task.FromResult(HealthCheckResult.Healthy());
    }
}
