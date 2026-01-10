namespace Company.Security.Abstractions.Repositories;

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

public sealed record SubjectDto
{
    public required Guid TenantId { get; init; }
    public required Guid OurSubject { get; init; }
    public required int TokenVersion { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
}
