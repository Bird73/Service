namespace Birdsoft.Security.Abstractions.Contracts.Auth;

using Birdsoft.Security.Abstractions;

public sealed record LoginResult(
    string Status,
    TokenPair? Tokens = null,
    MfaChallengeResponse? Mfa = null);
