namespace Company.Security.Abstractions.Repositories;

using Company.Security.Abstractions.Models;

/// <summary>
/// Subject Repository
/// </summary>
public interface ISubjectRepository
{
    Task<SubjectDto?> FindAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);

    Task<SubjectDto> CreateAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);

    Task<int> UpdateTokenVersionAsync(
        Guid tenantId,
        Guid ourSubject,
        int newVersion,
        CancellationToken cancellationToken = default);

    Task<int> IncrementTokenVersionAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);
}
