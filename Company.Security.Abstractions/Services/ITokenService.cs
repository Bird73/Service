namespace Company.Security.Abstractions.Services;

/// <summary>
/// Token 發行、刷新、撤銷服務
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// 為指定 subject 產生 Access Token + Refresh Token
    /// </summary>
    Task<TokenPair> GenerateTokensAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 使用 Refresh Token 換發新的 Token Pair（含 rotation）
    /// </summary>
    Task<RefreshResult> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 撤銷指定的 Refresh Token
    /// </summary>
    Task<RevokeResult> RevokeAsync(
        Guid tenantId,
        Guid ourSubject,
        string refreshToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 撤銷指定 subject 的所有 Refresh Token
    /// </summary>
    Task<int> RevokeAllAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);
}
