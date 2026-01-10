namespace Company.Security.Abstractions.Repositories;

/// <summary>
/// Tenant Repository
/// </summary>
public interface ITenantRepository
{
    Task<TenantDto?> FindAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task<TenantDto> CreateAsync(
        Guid tenantId,
        string name,
        CancellationToken cancellationToken = default);

    Task<int> IncrementTokenVersionAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);
}

public sealed record TenantDto
{
    public required Guid TenantId { get; init; }
    public required string Name { get; init; }
    public required int TokenVersion { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
}
