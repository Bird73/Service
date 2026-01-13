namespace Birdsoft.Security.Data.EfCore.Services;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;

public sealed class EfOidcProviderService : IOidcProviderService
{
    private readonly IOidcProviderRegistry _registry;

    public EfOidcProviderService(IOidcProviderRegistry registry)
    {
        _registry = registry;
    }

    public async Task<bool> IsTenantProviderEnabledAsync(Guid tenantId, string provider, CancellationToken cancellationToken = default)
    {
        var opts = await _registry.GetAsync(tenantId, provider, cancellationToken);
        return opts is not null;
    }

    public async Task<string> GetAuthorizationUrlAsync(
        Guid tenantId,
        string provider,
        string state,
        string nonce,
        string? redirectUri = null,
        CancellationToken cancellationToken = default)
    {
        _ = redirectUri;

        var opts = await _registry.GetAsync(tenantId, provider, cancellationToken);
        if (opts is null)
        {
            throw new InvalidOperationException("OIDC provider not enabled for this tenant.");
        }

        // For now (MVP), keep a deterministic local redirect usable in dev.
        // Real implementation should build an authorization URL against opts.Authority + discovery metadata.
        var cb = (opts.CallbackPath ?? "/api/v1/auth/oidc/{provider}/callback")
            .Replace("{provider}", Uri.EscapeDataString(provider), StringComparison.OrdinalIgnoreCase);

        return $"{cb}?code=stub-code&state={Uri.EscapeDataString(state)}&nonce={Uri.EscapeDataString(nonce)}";
    }

    public async Task<OidcUserInfo> ExchangeCodeAsync(
        Guid tenantId,
        string provider,
        string code,
        AuthStateContext ctx,
        string? redirectUri = null,
        CancellationToken cancellationToken = default)
    {
        _ = redirectUri;

        var opts = await _registry.GetAsync(tenantId, provider, cancellationToken);
        if (opts is null)
        {
            throw new InvalidOperationException("OIDC provider not enabled for this tenant.");
        }

        // MVP stub: allow tests to trigger nonce/pkce mismatch deterministically.
        // Format: "sub=<value>;n=<expectedNonce>;cv=<expectedCodeVerifier>" (any subset).
        var expectedNonce = TryGetParam(code, "n");
        var expectedCv = TryGetParam(code, "cv");
        var sub = TryGetParam(code, "sub") ?? code;

        if (!string.IsNullOrWhiteSpace(expectedNonce)
            && !string.Equals(expectedNonce, ctx.Nonce, StringComparison.Ordinal))
        {
            throw new OidcNonceMismatchException();
        }

        if (!string.IsNullOrWhiteSpace(expectedCv)
            && !string.Equals(expectedCv, ctx.CodeVerifier, StringComparison.Ordinal))
        {
            throw new OidcPkceMismatchException();
        }

        // Stub: map code to provider_sub; issuer uses configured issuer if present.
        return new OidcUserInfo
        {
            Issuer = opts.Issuer ?? opts.Authority ?? "https://example.invalid",
            ProviderSub = sub,
            Email = "stub@example.invalid",
            Name = "Stub User",
        };
    }

    private static string? TryGetParam(string input, string key)
    {
        if (string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        var parts = input.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            var idx = part.IndexOf('=');
            if (idx <= 0)
            {
                continue;
            }

            var k = part[..idx];
            var v = part[(idx + 1)..];
            if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase))
            {
                return v;
            }
        }

        return null;
    }
}
