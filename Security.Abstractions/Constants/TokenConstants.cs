namespace Birdsoft.Security.Abstractions.Constants;

public static class TokenConstants
{
    /// <summary>
    /// Increment when token claim structure semantics change.
    /// Breaking changes must bump this or use a new issuer.
    /// </summary>
    public const int TokenFormatVersion = 1;

    public const string TokenFormatVersionClaim = "token_fv";
    public const string EnvironmentIdClaim = "env";
    
    // V20: platform admin account governance
    // Monotonic per-platform-admin token version. Role changes / disable bump this value.
    public const string PlatformAdminTokenVersionClaim = "platform_admin_tv";
}
