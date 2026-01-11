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

        // Stub：把 code 映射成 provider_sub，issuer 固定。
        return Task.FromResult(new OidcUserInfo
        {
            Issuer = "https://example.invalid",
            ProviderSub = code,
            Email = "stub@example.invalid",
            Name = "Stub User",
        });
    }
}
