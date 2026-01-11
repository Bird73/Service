namespace Birdsoft.Security.Abstractions.Contracts.Auth;

public sealed record LoginRequest(
    string Username,
    string Password);
