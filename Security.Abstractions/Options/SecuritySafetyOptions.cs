namespace Birdsoft.Security.Abstractions.Options;

/// <summary>
/// Startup safety checks that prevent dangerous security misconfiguration.
/// </summary>
public sealed class SecuritySafetyOptions
{
    public const string SectionName = "Security:Safety";

    /// <summary>
    /// Enable startup validation. Defaults to enabled in non-Development environments.
    /// </summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// If true, require a non-empty Security:Environment:EnvironmentId.
    /// </summary>
    public bool RequireEnvironmentId { get; init; } = true;

    /// <summary>
    /// If true, enforce tenant isolation when JwtOptions has Tenants configured.
    /// </summary>
    public bool EnforceTenantJwtIsolation { get; init; } = true;
}
