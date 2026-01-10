namespace Birdsoft.Security.Abstractions.Contracts.Auth;

public sealed record TokenRevokeRequest(
    string? RefreshToken,
    bool AllDevices = false);
