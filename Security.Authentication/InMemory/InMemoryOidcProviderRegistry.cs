namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Stores;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;

public sealed class InMemoryOidcProviderRegistry : IOidcProviderRegistry
{
    private readonly ConcurrentDictionary<(Guid TenantId, string Provider), OidcProviderOptions> _options = new();

    public InMemoryOidcProviderRegistry(IOptionsMonitor<OidcProviderRegistryOptions> configured)
    {
        var fromConfig = configured.CurrentValue?.Providers ?? [];
        foreach (var p in fromConfig)
        {
            if (string.IsNullOrWhiteSpace(p.Provider))
            {
                continue;
            }

            _options[(Guid.Empty, p.Provider)] = p;
        }

        // Default stub provider for local flow testing unless overridden by config.
        if (!_options.ContainsKey((Guid.Empty, "stub")))
        {
            var stub = new OidcProviderOptions
            {
                Provider = "stub",
                Authority = "https://example.invalid",
                Issuer = "https://example.invalid",
                ClientId = "stub-client",
                ClientSecret = "stub-secret",
                CallbackPath = "/api/v1/auth/oidc/stub/callback",
                Scopes = ["openid", "profile", "email"],
            };

            _options[(Guid.Empty, "stub")] = stub;
        }
    }

    public ValueTask<OidcProviderOptions?> GetAsync(Guid tenantId, string provider, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (_options.TryGetValue((tenantId, provider), out var specific))
        {
            return ValueTask.FromResult<OidcProviderOptions?>(specific);
        }

        if (_options.TryGetValue((Guid.Empty, provider), out var fallback))
        {
            return ValueTask.FromResult<OidcProviderOptions?>(fallback);
        }

        return ValueTask.FromResult<OidcProviderOptions?>(null);
    }
}
