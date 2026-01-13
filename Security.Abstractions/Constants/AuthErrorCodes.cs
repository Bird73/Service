namespace Birdsoft.Security.Abstractions.Constants;

/// <summary>
/// 常見錯誤碼
/// </summary>
public static class AuthErrorCodes
{
    public const string InvalidRequest = "invalid_request";
    public const string InvalidCredentials = "invalid_credentials";
    public const string TenantMismatch = "tenant_mismatch";
    public const string TenantNotActive = "tenant_not_active";
    public const string UserNotActive = "user_not_active";
    public const string InvalidState = "invalid_state";
    public const string StateExpired = "state_expired";
    public const string ProviderNotEnabled = "provider_not_enabled";
    public const string InvalidToken = "invalid_token";
    public const string MissingBearerToken = "missing_bearer_token";
    public const string InvalidRefreshToken = "invalid_refresh_token";
    public const string RevokeFailed = "revoke_failed";
    public const string InternalError = "internal_error";
    public const string OidcError = "oidc_error";
    public const string OidcExchangeFailed = "oidc_exchange_failed";
    public const string ExternalIdentityDisabled = "external_identity_disabled";
    public const string MfaUnavailable = "mfa_unavailable";
    public const string MfaChallengeNotFound = "mfa_challenge_not_found";
    public const string MfaExpired = "mfa_expired";
    public const string MfaFailed = "mfa_failed";
    public const string MfaChallengeAlreadyUsed = "mfa_challenge_already_used";
    public const string ExpiredToken = "expired_token";
    public const string RevokedToken = "revoked_token";
    public const string TokenExpired = "token_expired";
    public const string TokenNotYetValid = "token_not_yet_valid";
    public const string TokenRevoked = "token_revoked";
    public const string TokenVersionMismatch = "token_version_mismatch";
    public const string RefreshTokenReuseDetected = "refresh_token_reuse_detected";
    public const string AccessTokenRevoked = "access_token_revoked";
    public const string RateLimited = "rate_limited";
    public const string BruteForceBlocked = "brute_force_blocked";
    public const string BruteForceDelayed = "brute_force_delayed";
    public const string UserNotFound = "user_not_found";
    public const string TenantNotFound = "tenant_not_found";
}
