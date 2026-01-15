using Birdsoft.Security.Abstractions.Models;

namespace Birdsoft.Security.Abstractions.Repositories;

/// <summary>
/// Refresh Token Repository
/// </summary>
public interface IRefreshTokenRepository
{
    Task<RefreshTokenDto> CreateAsync(
        Guid tenantId,
        Guid ourSubject,
        Guid sessionId,
        string tokenLookup,
        string tokenHash,
        DateTimeOffset expiresAt,
        int issuedTenantTokenVersion,
        int issuedSubjectTokenVersion,
        CancellationToken cancellationToken = default);

    Task<RefreshTokenDto?> FindByHashAsync(
        Guid tenantId,
        string tokenLookup,
        string tokenHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 嘗試進行 rotation：建立新 session row，並撤銷舊 session。
    /// 必須在同一交易中完成，避免併發導致雙花。
    /// </summary>
    Task<RefreshTokenDto?> TryRotateAsync(
        Guid tenantId,
        Guid ourSubject,
        Guid currentSessionId,
        string currentTokenLookup,
        string currentTokenHash,
        Guid newSessionId,
        string newTokenLookup,
        string newTokenHash,
        DateTimeOffset expiresAt,
        DateTimeOffset now,
        int issuedTenantTokenVersion,
        int issuedSubjectTokenVersion,
        string? revokeReason = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 撤銷指定 token（可選設定 replacedBy）
    /// </summary>
    Task<bool> RevokeAsync(
        Guid tenantId,
        Guid ourSubject,
        Guid sessionId,
        string tokenLookup,
        string tokenHash,
        DateTimeOffset revokedAt,
        string? revokeReason = null,
        Guid? replacedBySessionRecordId = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 撤銷指定 subject 的所有 refresh token
    /// </summary>
    Task<int> RevokeAllBySubjectAsync(
        Guid tenantId,
        Guid ourSubject,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 撤銷指定 session 的所有 refresh token（用於 refresh token reuse / 裝置異常等情境）。
    /// </summary>
    Task<int> RevokeAllBySessionAsync(
        Guid tenantId,
        Guid sessionId,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 清理過期的 refresh token
    /// </summary>
    Task<int> DeleteExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}
