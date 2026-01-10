namespace Birdsoft.Security.Authorization.Evaluation;

public sealed record AuthorizationDecision(
    bool Allowed,
    string? Reason = null)
{
    public static AuthorizationDecision Allow(string? reason = null) => new(true, reason);
    public static AuthorizationDecision Deny(string? reason = null) => new(false, reason);
}
