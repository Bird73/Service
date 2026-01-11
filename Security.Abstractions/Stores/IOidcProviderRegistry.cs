namespace Birdsoft.Security.Abstractions.Stores;

using Birdsoft.Security.Abstractions.Options;

/// <summary>
/// per-tenant 的 OIDC provider 設定來源。
/// </summary>
public interface IOidcProviderRegistry
{
    ValueTask<OidcProviderOptions?> GetAsync(
        Guid tenantId,
        string provider,
        CancellationToken cancellationToken = default);
}
