namespace Birdsoft.Security.Abstractions.Contracts.Auth;

public sealed record LogoutResponse(
    int RevokedRefreshTokens);
