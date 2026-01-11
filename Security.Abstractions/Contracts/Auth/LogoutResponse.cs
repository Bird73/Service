namespace Birdsoft.Security.Abstractions.Contracts.Auth;

[Obsolete("Use TokenRevokeResponse. /logout is a legacy alias of /token/revoke.")]
public sealed record LogoutResponse(
    int RevokedRefreshTokens);
