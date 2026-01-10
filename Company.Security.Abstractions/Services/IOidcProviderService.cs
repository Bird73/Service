namespace Company.Security.Abstractions.Services;

using Company.Security.Abstractions.Models;

/// <summary>
/// OIDC Provider 服務（取得授權 URL、交換 code、驗證 id_token）
/// </summary>
public interface IOidcProviderService
{
    /// <summary>
    /// 檢查 tenant 是否啟用指定的 provider
    /// </summary>
    Task<bool> IsTenantProviderEnabledAsync(
        Guid tenantId,
        string provider,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 取得 OIDC 授權 URL
    /// </summary>
    Task<string> GetAuthorizationUrlAsync(
        Guid tenantId,
        string provider,
        string state,
        string? redirectUri = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 以 authorization code 交換 token 並驗證，回傳使用者資訊
    /// </summary>
    Task<OidcUserInfo> ExchangeCodeAsync(
        Guid tenantId,
        string provider,
        string code,
        AuthStateContext ctx,
        string? redirectUri = null,
        CancellationToken cancellationToken = default);
}
