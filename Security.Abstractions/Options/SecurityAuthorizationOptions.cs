namespace Birdsoft.Security.Abstractions.Options;

/// <summary>
/// Authorization safety/configuration options.
/// These are intentionally conservative: defaults are fail-closed.
/// </summary>
public sealed class SecurityAuthorizationOptions
{
    public const string SectionName = "Security:Authorization";

    /// <summary>
    /// Explicit escape hatch for development only.
    /// When true, guardrails will not fail-fast if an allow-all store is injected.
    /// Default is false.
    /// </summary>
    public bool UnsafeDevMode { get; init; }

    /// <summary>
    /// Public permissions are allowed only when the permission key matches one of these prefixes,
    /// or is explicitly listed in <see cref="PublicPermissions"/>.
    /// Default: "public:".
    /// </summary>
    public string[] PublicPermissionPrefixes { get; init; } = ["public:"];

    /// <summary>
    /// Explicit allow-list of public permissions.
    /// </summary>
    public string[] PublicPermissions { get; init; } = [];

    /// <summary>
    /// Any permission key matching one of these prefixes MUST be product-bound in the catalog.
    /// If the catalog returns a public permission for one of these prefixes, evaluators must deny.
    /// </summary>
    public string[] RequiredProductPrefixes { get; init; } = [];

    /// <summary>
    /// In non-EF/in-memory mode, the permission catalog is seeded via configuration.
    /// Unknown permission keys MUST resolve to null.
    /// </summary>
    public PermissionCatalogSeedEntry[] PermissionCatalog { get; init; } = [];

    /// <summary>
    /// In non-EF/in-memory mode, entitlements are seeded via configuration.
    /// If no matching entry exists, entitlement MUST be treated as disabled.
    /// </summary>
    public TenantEntitlementSeedEntry[] TenantEntitlements { get; init; } = [];

    public sealed record PermissionCatalogSeedEntry(string PermissionKey, string? ProductKey);

    public sealed record TenantEntitlementSeedEntry(
        Guid TenantId,
        string ProductKey,
        bool Enabled,
        DateTimeOffset? StartAt,
        DateTimeOffset? EndAt);
}
