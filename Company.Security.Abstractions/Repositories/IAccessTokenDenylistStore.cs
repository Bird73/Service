namespace Company.Security.Abstractions.Repositories;

/// <summary>
/// Access Token 即時撤銷（denylist）。
///
/// 用途：若需要在 access token 有效期內「立即失效」，需將 (tenant_id, jti) 加入 denylist 並在每次驗證 JWT 時查核。
/// 建議實作：Redis / Distributed cache；保存期限至少到 token exp。
/// </summary>
public interface IAccessTokenDenylistStore
{
    Task AddAsync(
        Guid tenantId,
        string jti,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    Task<bool> ContainsAsync(
        Guid tenantId,
        string jti,
        CancellationToken cancellationToken = default);
}
