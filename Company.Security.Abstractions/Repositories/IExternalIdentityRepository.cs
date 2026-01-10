namespace Company.Security.Abstractions.Repositories;

using Company.Security.Abstractions.Models;

/// <summary>
/// 外部身份 Repository
/// </summary>
public interface IExternalIdentityRepository
{
    Task<ExternalIdentityDto?> FindAsync(
        Guid tenantId,
        string provider,
        string issuer,
        string providerSub,
        CancellationToken cancellationToken = default);

    Task<ExternalIdentityDto> CreateAsync(
        Guid tenantId,
        Guid ourSubject,
        string provider,
        string issuer,
        string providerSub,
        CancellationToken cancellationToken = default);
}
