namespace Birdsoft.Security.Authentication.Tenancy;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Tenancy;
using System.Security.Claims;

public static class HttpContextTenantExtensions
{
    private const string TenantContextItemKey = "Birdsoft.Security.TenantContext";

    public static TenantContext GetTenantContext(this HttpContext httpContext)
    {
        if (httpContext.Items.TryGetValue(TenantContextItemKey, out var value) && value is TenantContext tenant)
        {
            return tenant;
        }

        var claim = httpContext.User?.FindFirstValue(SecurityClaimTypes.TenantId);
        if (Guid.TryParse(claim, out var tenantId))
        {
            tenant = new TenantContext(tenantId, TenantResolutionSource.TokenClaim);
            httpContext.Items[TenantContextItemKey] = tenant;
            return tenant;
        }

        throw new InvalidOperationException("TenantContext not resolved.");
    }

    internal static void SetTenantContext(this HttpContext httpContext, TenantContext tenant)
    {
        httpContext.Items[TenantContextItemKey] = tenant;
    }
}
