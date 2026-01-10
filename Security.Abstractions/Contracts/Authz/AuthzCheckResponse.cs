namespace Birdsoft.Security.Abstractions.Contracts.Authz;

public sealed record AuthzCheckResponse(
    bool Allowed,
    string? Reason = null);
