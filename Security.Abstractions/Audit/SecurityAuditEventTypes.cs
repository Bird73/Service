namespace Birdsoft.Security.Abstractions.Audit;

/// <summary>
/// Stable event type identifiers for security audit.
/// These values are persisted; do not rename existing keys.
/// </summary>
public static class SecurityAuditEventTypes
{
    public const string AuthLoginSuccess = "Auth.Login.Success";
    public const string AuthLoginFailed = "Auth.Login.Failed";

    public const string AuthExternalLoginSuccess = "Auth.ExternalLogin.Success";
    public const string AuthExternalLoginFailed = "Auth.ExternalLogin.Failed";

    public const string AuthTokenIssued = "Auth.Token.Issued";
    public const string AuthTokenRefreshed = "Auth.Token.Refreshed";
    public const string AuthTokenRevoked = "Auth.Token.Revoked";

    public const string AuthSubjectLocked = "Auth.Subject.Locked";
    public const string AuthSubjectDisabled = "Auth.Subject.Disabled";

    public const string AuthRoleAssigned = "Auth.Role.Assigned";
    public const string AuthRoleRevoked = "Auth.Role.Revoked";
}
