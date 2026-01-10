namespace Company.Security.Abstractions.Repositories;

/// <summary>
/// Refresh Token Repository
/// </summary>
public interface IRefreshTokenRepository
{
    Task CreateAsync(
        Guid tenantId,
        Guid ourSubject,
        string tokenHash,
        DateTimeOffset expiresAt,
        int issuedTenantTokenVersion,
        int issuedSubjectTokenVersion,
        CancellationToken cancellationToken = default);

    Task<RefreshTokenDto?> FindByHashAsync(
        string tokenHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 撤銷指定 token（可選設定 replacedBy）
    /// </summary>
    Task<bool> RevokeAsync(
        string tokenHash,
        DateTimeOffset revokedAt,
        Guid? replacedByTokenId = null,
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
    /// 清理過期的 refresh token
    /// </summary>
    Task<int> DeleteExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public sealed record RefreshTokenDto
{
    public required Guid Id { get; init; }
    public required Guid TenantId { get; init; }
    public required Guid OurSubject { get; init; }
    public required string TokenHash { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? RevokedAt { get; init; }
    public Guid? ReplacedByRefreshTokenId { get; init; }
    public required int IssuedTenantTokenVersion { get; init; }
    public required int IssuedSubjectTokenVersion { get; init; }

    public bool IsValid(DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;
}
