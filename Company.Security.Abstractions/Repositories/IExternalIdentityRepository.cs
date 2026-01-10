namespace Company.Security.Abstractions.Repositories;

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

public sealed record ExternalIdentityDto
{
    public required Guid TenantId { get; init; }
    public required Guid OurSubject { get; init; }
    public required string Provider { get; init; }
    public required string Issuer { get; init; }
    public required string ProviderSub { get; init; }
}
