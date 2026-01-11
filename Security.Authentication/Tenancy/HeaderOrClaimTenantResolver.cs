namespace Birdsoft.Security.Authentication.Tenancy;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Tenancy;

public sealed class HeaderOrClaimTenantResolver : ITenantResolver
{
    public const string TenantHeaderName = "X-Tenant-Id";

    public bool TryResolve(TenantResolveInput input, out TenantContext tenant)
    {
        if (input.Claims.TryGetValue(SecurityClaimTypes.TenantId, out var claim) && Guid.TryParse(claim, out var tenantIdFromClaim))
        {
            tenant = new TenantContext(tenantIdFromClaim, TenantResolutionSource.TokenClaim);
            return true;
        }

        if (input.Headers.TryGetValue(TenantHeaderName, out var header) && Guid.TryParse(header, out var tenantIdFromHeader))
        {
            tenant = new TenantContext(tenantIdFromHeader, TenantResolutionSource.Header);
            return true;
        }

        tenant = new TenantContext(Guid.Empty, TenantResolutionSource.Unknown);
        return false;
    }
}
