namespace Birdsoft.Security.Abstractions.Contracts.Auth;

[Obsolete("Use TokenRevokeRequest. /logout is a legacy alias of /token/revoke.")]
public sealed record LogoutRequest(
    string? RefreshToken,
    bool AllDevices = false);
