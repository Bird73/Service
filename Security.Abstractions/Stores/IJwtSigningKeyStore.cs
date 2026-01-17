namespace Birdsoft.Security.Abstractions.Stores;

public enum JwtSigningKeyStatus
{
    Active = 1,
    Inactive = 2,
    Disabled = 3,
}

public sealed record JwtSigningKeyRecord(
    string Kid,
    string Algorithm,
    JwtSigningKeyStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record JwtSigningKeySigningMaterial(
    string Kid,
    string Algorithm,
    string? PrivateKeyPem,
    string? SymmetricKey);

public sealed record JwtSigningKeyVerificationMaterial(
    string Kid,
    string Algorithm,
    string? PublicKeyPem,
    string? SymmetricKey);

/// <summary>
/// JWT signing key governance.
/// - At most one key should be Active at a time.
/// - Inactive keys remain available for verification.
/// - Disabled keys are ignored for both signing and verification.
/// </summary>
public interface IJwtSigningKeyStore
{
    Task<bool> HasAnyAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<JwtSigningKeyRecord>> ListAsync(bool includeDisabled = false, CancellationToken cancellationToken = default);

    Task<JwtSigningKeyRecord?> FindAsync(string kid, CancellationToken cancellationToken = default);

    Task<JwtSigningKeyRecord?> GetActiveAsync(CancellationToken cancellationToken = default);

    Task<JwtSigningKeySigningMaterial?> GetActiveSigningMaterialAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<JwtSigningKeyVerificationMaterial>> GetVerificationKeysAsync(CancellationToken cancellationToken = default);

    Task<JwtSigningKeyRecord> CreateRsaAsync(string? kid = null, string? reason = null, CancellationToken cancellationToken = default);

    Task<JwtSigningKeyRecord> RotateRsaAsync(string? reason = null, CancellationToken cancellationToken = default);

    Task<JwtSigningKeyRecord> CreateHmacAsync(string? kid = null, int bytes = 32, string? reason = null, CancellationToken cancellationToken = default);

    Task<JwtSigningKeyRecord> RotateHmacAsync(int bytes = 32, string? reason = null, CancellationToken cancellationToken = default);

    Task<JwtSigningKeyRecord?> DisableAsync(string kid, string? reason = null, CancellationToken cancellationToken = default);
}
