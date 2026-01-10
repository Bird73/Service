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
    /// 標記為已使用（原子性）
    /// </summary>
    Task<bool> TryConsumeAsync(
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
}
