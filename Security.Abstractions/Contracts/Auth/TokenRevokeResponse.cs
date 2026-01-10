namespace Birdsoft.Security.Abstractions.Contracts.Auth;

public sealed record TokenRevokeResponse(
    int RevokedRefreshTokens);
