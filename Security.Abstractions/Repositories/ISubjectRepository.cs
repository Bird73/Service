namespace Birdsoft.Security.Abstractions.Repositories;

using Birdsoft.Security.Abstractions.Models;

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

    Task<int> UpdateStatusAsync(
        Guid tenantId,
        Guid ourSubject,
        UserStatus status,
        CancellationToken cancellationToken = default);
}
