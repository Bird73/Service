namespace Birdsoft.Security.Authentication.Tenancy;

using Birdsoft.Security.Abstractions.Tenancy;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

public sealed class TenantResolutionMiddleware : IMiddleware
{
    private readonly ITenantResolver _resolver;
    private readonly TenantContextAccessor _accessor;

    public TenantResolutionMiddleware(ITenantResolver resolver, TenantContextAccessor accessor)
    {
        _resolver = resolver;
        _accessor = accessor;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (IsOidcCallback(context.Request.Path))
        {
            await next(context);
            return;
        }

        var input = new TenantResolveInput(
            Host: context.Request.Host.HasValue ? context.Request.Host.Value : null,
            Path: context.Request.Path.HasValue ? context.Request.Path.Value : null,
            Headers: context.Request.Headers.ToDictionary(h => h.Key, h => (string?)h.Value.ToString(), StringComparer.OrdinalIgnoreCase),
            Claims: context.User?.Claims
                .GroupBy(c => c.Type, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.FirstOrDefault()?.Value, StringComparer.OrdinalIgnoreCase)
                ?? new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase));

        if (_resolver.TryResolve(input, out var tenant) && tenant.TenantId != Guid.Empty)
        {
            _accessor.Current = tenant;
            context.SetTenantContext(tenant);
            await next(context);
            return;
        }

        // For auth endpoints, tenant is required (header or token claim). Missing tenant must not become 500.
        if (RequiresTenant(context.Request.Path))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(ApiResponse<object>.Fail("invalid_request", "X-Tenant-Id (or tenant_id claim) is required"));
            return;
        }

        await next(context);
    }

    private static bool RequiresTenant(PathString path)
    {
        if (!path.HasValue)
        {
            return false;
        }

        var p = path.Value ?? string.Empty;
        if (p.Length == 0)
        {
            return false;
        }

        // Only auth endpoints require tenant resolution.
        if (p.StartsWith("/api/v1/auth", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Legacy root group.
        if (p.StartsWith("/auth", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static bool IsOidcCallback(PathString path)
    {
        if (!path.HasValue)
        {
            return false;
        }

        var p = path.Value ?? string.Empty;
        if (p.Length == 0)
        {
            return false;
        }

        // /api/v1/auth/oidc/{provider}/callback
        if (p.StartsWith("/api/v1/auth/oidc/", StringComparison.OrdinalIgnoreCase)
            && p.EndsWith("/callback", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // legacy: /auth/oidc/{provider}/callback
        if (p.StartsWith("/auth/oidc/", StringComparison.OrdinalIgnoreCase)
            && p.EndsWith("/callback", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
}
