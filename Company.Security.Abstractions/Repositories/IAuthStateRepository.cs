namespace Company.Security.Abstractions.Repositories;

/// <summary>
/// Auth State Repository
/// </summary>
public interface IAuthStateRepository
{
    Task CreateAsync(
        string state,
        Guid tenantId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    Task<AuthStateDto?> FindAsync(
        string state,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 將 OIDC 需要的 context 綁定到 state（例如 code_verifier、nonce）。
    ///
    /// 規則：只允許 attach 一次；若已 attach/已用/已過期/不存在，回傳 false。
    /// </summary>
    Task<bool> TryAttachOidcContextAsync(
        string state,
        string codeVerifier,
        string nonce,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 標記為已使用（原子性）
    /// </summary>
    Task<bool> TryConsumeAsync(
        string state,
        DateTimeOffset usedAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 原子性地「讀出 state + context」並標記 used。
    ///
    /// - 不存在/已用/已過期：回傳 null
    /// - 成功：回傳完整 DTO（含 tenant_id, code_verifier, nonce），並保證 used_at 已寫入
    /// </summary>
    Task<AuthStateDto?> TryConsumeAndGetAsync(
        string state,
        DateTimeOffset usedAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 清理過期或已使用的 state
    /// </summary>
    Task<int> DeleteExpiredOrUsedAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public sealed record AuthStateDto
{
    public required string State { get; init; }
    public required Guid TenantId { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? UsedAt { get; init; }

    public string? CodeVerifier { get; init; }
    public string? Nonce { get; init; }
}
