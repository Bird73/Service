namespace Birdsoft.Security.Abstractions.Mfa;

public sealed record MfaChallenge(
    Guid ChallengeId,
    Guid TenantId,
    Guid OurSubject,
    DateTimeOffset ExpiresAt,
    string? ProviderHint = null);

public interface IMfaChallengeStore
{
    Task<MfaChallenge> CreateAsync(Guid tenantId, Guid ourSubject, TimeSpan ttl, string? providerHint = null, CancellationToken cancellationToken = default);
    Task<MfaChallenge?> FindAsync(Guid challengeId, CancellationToken cancellationToken = default);
    Task<bool> ConsumeAsync(Guid challengeId, CancellationToken cancellationToken = default);
}
