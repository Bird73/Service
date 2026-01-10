namespace Birdsoft.Security.Authentication.Tenancy;

using Birdsoft.Security.Abstractions.Tenancy;
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
        }

        await next(context);
    }
}
