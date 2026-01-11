namespace Birdsoft.Security.Abstractions.Contracts.Auth;

public sealed record MfaChallengeResponse(
    Guid ChallengeId,
    DateTimeOffset ExpiresAt,
    bool MfaRequired = true,
    string? ProviderHint = null);
