namespace Company.Security.Abstractions.Services;

/// <summary>
/// OIDC 一次性 State 服務
/// </summary>
public interface IAuthStateService
{
    /// <summary>
    /// 為指定 tenant 建立一次性 state（5 分鐘有效）
    /// </summary>
    Task<AuthStateInfo> CreateStateAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 驗證 state 並取得對應的 tenant（不消耗）
    /// </summary>
    Task<Guid?> ValidateAndGetTenantAsync(
        string state,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 將 OIDC 需要的 context（PKCE code_verifier、nonce）綁定到 state。
    ///
    /// 規則：若 state 不存在/已使用/已過期，應回傳 false。
    /// </summary>
    Task<bool> TryAttachOidcContextAsync(
        string state,
        string codeVerifier,
        string nonce,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 消耗 state（一次性）並回傳 OIDC callback 需要的完整 context；若已使用或不存在則回傳 null。
    /// </summary>
    Task<AuthStateContext?> ConsumeStateAsync(
        string state,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 清理過期或已使用的 state
    /// </summary>
    Task<int> CleanupExpiredStatesAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}
