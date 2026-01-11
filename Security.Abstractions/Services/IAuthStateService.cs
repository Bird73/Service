namespace Birdsoft.Security.Abstractions.Services;

using Birdsoft.Security.Abstractions.Models;

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
    /// 狀態機規則（需可預期）：
    /// - state 不存在 / 已過期 / 已 used：回傳 false
    /// - 尚未 attach：允許 attach 一次，成功回傳 true
    /// - 已 attach：應回傳 false（不覆寫），避免 client 端 race 導致 verifier/nonce 不一致
    /// </summary>
    Task<bool> TryAttachOidcContextAsync(
        string state,
        string codeVerifier,
        string nonce,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 消耗 state（一次性）並回傳 OIDC callback 需要的完整 context；若已使用或不存在則回傳 null。
    ///
    /// 實作要求：必須在「單一交易/原子操作」中，同時讀出 tenant_id + verifier + nonce 並標記 used_at，避免 TOCTOU。
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
