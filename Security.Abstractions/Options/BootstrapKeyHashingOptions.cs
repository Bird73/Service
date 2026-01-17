namespace Birdsoft.Security.Abstractions.Options;

/// <summary>
/// Hashing options for bootstrap keys stored in the database.
/// </summary>
public sealed class BootstrapKeyHashingOptions
{
    public const string SectionName = "Security:BootstrapKeyHashing";

    /// <summary>
    /// Required pepper for HMAC hashing. Treat like a secret.
    /// </summary>
    public string Pepper { get; init; } = string.Empty;
}
