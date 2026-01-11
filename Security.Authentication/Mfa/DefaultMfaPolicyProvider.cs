namespace Birdsoft.Security.Authentication.Mfa;

using Birdsoft.Security.Abstractions.Mfa;
using Microsoft.Extensions.Options;

public sealed class DefaultMfaPolicyProvider : IMfaPolicyProvider
{
    private readonly IOptionsMonitor<MfaOptions> _options;

    public DefaultMfaPolicyProvider(IOptionsMonitor<MfaOptions> options) => _options = options;

    public Task<MfaPolicy> GetPolicyAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = ourSubject;
        _ = cancellationToken;

        var opts = _options.CurrentValue;
        if (opts.TenantOverrides.TryGetValue(tenantId.ToString(), out var policy))
        {
            return Task.FromResult(policy);
        }

        return Task.FromResult(opts.DefaultPolicy);
    }
}
