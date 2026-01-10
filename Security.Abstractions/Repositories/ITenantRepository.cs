namespace Birdsoft.Security.Abstractions.Repositories;

using Birdsoft.Security.Abstractions.Models;

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
