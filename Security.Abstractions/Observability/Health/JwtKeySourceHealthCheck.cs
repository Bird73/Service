namespace Birdsoft.Security.Abstractions.Observability.Health;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Services;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using System.Collections;

public sealed class JwtKeySourceHealthCheck : IHealthCheck
{
    private readonly IJwksProvider _keys;
    private readonly IOptionsMonitor<JwtOptions> _jwtOptions;

    public JwtKeySourceHealthCheck(IJwksProvider keys, IOptionsMonitor<JwtOptions> jwtOptions)
    {
        _keys = keys;
        _jwtOptions = jwtOptions;
    }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        _ = context;
        _ = cancellationToken;

        var opts = _jwtOptions.CurrentValue;
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
            var jwks = _keys.GetJwksDocument();
            if (jwks is null)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("JWKS is null"));
            }

            var keysCount = TryGetJwksKeysCount(jwks);
            if (keysCount is 0)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("JWKS has no keys"));
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("JWT key provider failure", ex));
        }

        return Task.FromResult(HealthCheckResult.Healthy());
    }

    private static int? TryGetJwksKeysCount(object jwks)
    {
        var t = jwks.GetType();
        var prop = t.GetProperty("keys") ?? t.GetProperty("Keys");
        if (prop is null)
        {
            return null;
        }

        var value = prop.GetValue(jwks);
        if (value is null)
        {
            return 0;
        }

        if (value is Array a)
        {
            return a.Length;
        }

        if (value is ICollection c)
        {
            return c.Count;
        }

        if (value is IEnumerable e)
        {
            var count = 0;
            foreach (var _ in e)
            {
                count++;
                if (count > 0)
                {
                    return count;
                }
            }

            return 0;
        }

        return null;
    }
}
