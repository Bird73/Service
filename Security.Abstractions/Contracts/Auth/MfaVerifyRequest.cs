namespace Birdsoft.Security.Abstractions.Contracts.Auth;

public sealed record MfaVerifyRequest(
    Guid ChallengeId,
    string Code);
