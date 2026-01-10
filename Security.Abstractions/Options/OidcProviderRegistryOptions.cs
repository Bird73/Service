namespace Birdsoft.Security.Abstractions.Options;

public sealed class OidcProviderRegistryOptions
{
    public const string SectionName = "Security:OidcProviders";

    /// <summary>
    /// Global provider defaults. Per-tenant enablement/overrides are handled by the registry implementation.
    /// </summary>
    public IReadOnlyList<OidcProviderOptions> Providers { get; init; } = [];
}
