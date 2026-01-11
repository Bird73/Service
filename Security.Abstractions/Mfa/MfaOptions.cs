namespace Birdsoft.Security.Abstractions.Mfa;

public sealed record MfaOptions
{
    public const string SectionName = "Mfa";

    public MfaPolicy DefaultPolicy { get; init; } = MfaPolicy.Disabled;

    /// <summary>
    /// Optional per-tenant overrides.
    /// Keys are tenantId as string.
    /// </summary>
    public Dictionary<string, MfaPolicy> TenantOverrides { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// If MFA is required but provider is unavailable, allow issuing tokens (and emit an audit event with Outcome=skip).
    /// Default is fail closed for MFA stage.
    /// </summary>
    public bool AllowSkipOnProviderFailure { get; init; } = false;
}
