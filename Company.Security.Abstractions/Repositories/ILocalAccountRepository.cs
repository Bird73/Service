namespace Company.Security.Abstractions.Repositories;

using Company.Security.Abstractions.Models;

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
