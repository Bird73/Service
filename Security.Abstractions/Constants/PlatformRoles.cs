namespace Birdsoft.Security.Abstractions.Constants;

public static class PlatformRoles
{
    // V20 platform admin role tiers
    public const string SuperAdmin = "platform.super_admin";
    public const string OpsAdmin = "platform.ops_admin";
    public const string ReadonlyAdmin = "platform.readonly_admin";

    // Legacy / transitional
    public const string LegacyPlatformAdmin = "platform_admin";
}
