namespace Birdsoft.Security.Abstractions.Stores;

public enum BootstrapKeyStatus
{
    Active = 1,
    Revoked = 2,
    Expired = 3,
}

public sealed record BootstrapKeyRecord(
    Guid Id,
    string Label,
    BootstrapKeyStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? RevokedAt,
    string? RevocationReason);

public sealed record BootstrapKeyCreateResult(
    BootstrapKeyRecord Record,
    string PlaintextKey);

/// <summary>
/// Governance store for platform bootstrap keys.
/// Keys are stored as one-way hashes and validated via constant-time comparison.
/// </summary>
public interface IBootstrapKeyStore
{
    Task<bool> HasAnyAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<BootstrapKeyRecord>> ListAsync(bool includeRevoked = false, CancellationToken cancellationToken = default);

    Task<BootstrapKeyCreateResult> CreateAsync(
        string? label = null,
        DateTimeOffset? expiresAt = null,
        CancellationToken cancellationToken = default);

    Task<bool> ValidateAsync(string providedKey, DateTimeOffset now, CancellationToken cancellationToken = default);

    Task<BootstrapKeyRecord?> RevokeAsync(Guid id, string? reason = null, CancellationToken cancellationToken = default);
}
