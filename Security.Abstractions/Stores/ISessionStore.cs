namespace Birdsoft.Security.Abstractions.Stores;

public interface ISessionStore
{
    Task<Guid> CreateSessionAsync(
        Guid tenantId,
        Guid ourSubject,
        DateTimeOffset createdAt,
        CancellationToken cancellationToken = default);

    Task<bool> IsSessionActiveAsync(
        Guid tenantId,
        Guid sessionId,
        CancellationToken cancellationToken = default);

    Task<bool> TerminateSessionAsync(
        Guid tenantId,
        Guid sessionId,
        DateTimeOffset terminatedAt,
        string? reason = null,
        CancellationToken cancellationToken = default);

    Task<int> TerminateAllAsync(
        Guid tenantId,
        Guid ourSubject,
        DateTimeOffset terminatedAt,
        string? reason = null,
        CancellationToken cancellationToken = default);
}
