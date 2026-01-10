namespace Birdsoft.Security.Abstractions.Contracts.Auth;

public sealed record LogoutRequest(
    string? RefreshToken,
    bool AllDevices = false);
