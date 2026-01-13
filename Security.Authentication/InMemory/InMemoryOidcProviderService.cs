namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Services;

public sealed class InMemoryOidcProviderService : IOidcProviderService
{
    public Task<bool> IsTenantProviderEnabledAsync(Guid tenantId, string provider, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = cancellationToken;
        return Task.FromResult(string.Equals(provider, "stub", StringComparison.OrdinalIgnoreCase));
    }

    public Task<string> GetAuthorizationUrlAsync(
        Guid tenantId,
        string provider,
        string state,
        string nonce,
        string? redirectUri = null,
        CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = redirectUri;
        _ = cancellationToken;

        // 這裡僅回傳可用於本機測試的假 URL。
        var url = $"/api/v1/auth/oidc/{Uri.EscapeDataString(provider)}/callback?code=stub-code&state={Uri.EscapeDataString(state)}&nonce={Uri.EscapeDataString(nonce)}";
        return Task.FromResult(url);
    }

    public Task<OidcUserInfo> ExchangeCodeAsync(
        Guid tenantId,
        string provider,
        string code,
        AuthStateContext ctx,
        string? redirectUri = null,
        CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = provider;
        _ = redirectUri;
        _ = cancellationToken;

        // Support security-negative tests by encoding expected bindings into the code value.
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

        // Stub：把 code 映射成 provider_sub，issuer 固定。
        return Task.FromResult(new OidcUserInfo
        {
            Issuer = "https://example.invalid",
            ProviderSub = sub,
            Email = "stub@example.invalid",
            Name = "Stub User",
        });
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
