namespace Company.Security.Abstractions.Repositories;

/// <summary>
/// 本地帳號 Repository
/// </summary>
public interface ILocalAccountRepository
{
    Task<LocalAccountDto?> FindByUsernameAsync(
        Guid tenantId,
        string usernameOrEmail,
        CancellationToken cancellationToken = default);

    Task<LocalAccountDto> CreateAsync(
        Guid tenantId,
        Guid ourSubject,
        string usernameOrEmail,
        string passwordHash,
        CancellationToken cancellationToken = default);
}

public sealed record LocalAccountDto
{
    public required Guid TenantId { get; init; }
    public required Guid OurSubject { get; init; }
    public required string UsernameOrEmail { get; init; }
    public required string PasswordHash { get; init; }
}
