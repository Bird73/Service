namespace Birdsoft.Security.Abstractions.Options;

/// <summary>
/// OIDC Provider 設定（支援 per-tenant：由 registry 依 tenantId 回傳對應設定）。
/// </summary>
public sealed class OidcProviderOptions
{
    /// <summary>
    /// Provider 代號（路由用，例如 google / line / microsoft）。
    /// </summary>
    public string Provider { get; init; } = string.Empty;

    /// <summary>
    /// Authority（Discovery endpoint base），例如 https://accounts.google.com
    /// </summary>
    public string? Authority { get; init; }

    /// <summary>
    /// Issuer（預期的 id_token iss）。若未設定，通常取 discovery 的 issuer。
    /// </summary>
    public string? Issuer { get; init; }

    public string ClientId { get; init; } = string.Empty;

    public string ClientSecret { get; init; } = string.Empty;

    /// <summary>
    /// Callback path（例如 /auth/oidc/google/callback）
    /// </summary>
    public string CallbackPath { get; init; } = "/auth/oidc/{provider}/callback";

    /// <summary>
    /// OIDC scopes（例如 openid, profile, email）。
    /// </summary>
    public IReadOnlyList<string> Scopes { get; init; } = ["openid", "profile", "email"];
}
