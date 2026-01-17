namespace Birdsoft.Security.Abstractions.Stores;

using Birdsoft.Security.Abstractions.Constants;

public enum PlatformAdminStatus
{
    Active = 1,
    Disabled = 2,
}

public sealed record PlatformAdminRecord(
    Guid OurSubject,
    string Role,
    PlatformAdminStatus Status,
    long TokenVersion,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

/// <summary>
/// Platform admin account governance (role assignment + enable/disable) with immediate token invalidation.
/// </summary>
public interface IPlatformAdminStore
{
    ValueTask<PlatformAdminRecord?> FindAsync(Guid ourSubject, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<PlatformAdminRecord>> ListAsync(int skip, int take, CancellationToken cancellationToken = default);

    Task<PlatformAdminRecord> CreateAsync(Guid ourSubject, string role, string? reason = null, CancellationToken cancellationToken = default);

    Task<PlatformAdminRecord?> SetRoleAsync(Guid ourSubject, string role, string? reason = null, CancellationToken cancellationToken = default);

    Task<PlatformAdminRecord?> SetStatusAsync(Guid ourSubject, PlatformAdminStatus status, string? reason = null, CancellationToken cancellationToken = default);
}
