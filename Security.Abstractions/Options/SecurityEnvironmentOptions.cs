namespace Birdsoft.Security.Abstractions.Options;

/// <summary>
/// Environment identity used to enforce cross-environment security isolation.
/// Tokens issued in one environment must not validate in another.
/// </summary>
public sealed class SecurityEnvironmentOptions
{
    public const string SectionName = "Security:Environment";

    /// <summary>
    /// Stable environment identifier (e.g. dev / stg / prod or a GUID).
    /// Recommended to be unique per deployment environment.
    /// </summary>
    public string EnvironmentId { get; init; } = string.Empty;
}
