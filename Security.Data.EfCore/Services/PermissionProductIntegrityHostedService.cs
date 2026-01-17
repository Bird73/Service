namespace Birdsoft.Security.Data.EfCore.Services;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

/// <summary>
/// Startup governance check: permission/product relationships must be consistent.
///
/// Rules:
/// - If a permission key matches any RequiredProductPrefixes, it MUST have ProductKey.
/// - If a permission has ProductKey, the product MUST exist and be enabled.
/// </summary>
public sealed class PermissionProductIntegrityHostedService : IHostedService
{
    private readonly IServiceProvider _services;
    private readonly IOptionsMonitor<SecurityAuthorizationOptions> _authzOptions;

    public PermissionProductIntegrityHostedService(
        IServiceProvider services,
        IOptionsMonitor<SecurityAuthorizationOptions> authzOptions)
    {
        _services = services;
        _authzOptions = authzOptions;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetService<SecurityDbContext>();
        if (db is null)
        {
            return;
        }

        // Some hosts/tests wire EF services after Program.cs decides whether to enable EF.
        // Ensure the schema exists before issuing governance queries.
        await db.Database.EnsureCreatedAsync(cancellationToken);

        var opts = _authzOptions.CurrentValue;
        var requiredPrefixes = (opts.RequiredProductPrefixes ?? Array.Empty<string>())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .ToArray();

        // Nothing to validate.
        if (requiredPrefixes.Length == 0)
        {
            // Still validate that product-bound permissions point to existing+enabled products.
        }

        var permissions = await db.Permissions.AsNoTracking()
            .Select(p => new { p.PermKey, p.ProductKey })
            .ToListAsync(cancellationToken);

        if (permissions.Count == 0)
        {
            return;
        }

        var productKeys = permissions
            .Select(p => p.ProductKey)
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Select(k => k!.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var products = await db.Products.AsNoTracking()
            .Where(p => productKeys.Contains(p.ProductKey))
            .Select(p => new { p.ProductKey, p.Status })
            .ToListAsync(cancellationToken);

        var productStatusByKey = products.ToDictionary(x => x.ProductKey, x => (ProductStatus)x.Status, StringComparer.Ordinal);

        foreach (var perm in permissions)
        {
            var permKey = (perm.PermKey ?? string.Empty).Trim();
            var pk = string.IsNullOrWhiteSpace(perm.ProductKey) ? null : perm.ProductKey.Trim();

            if (requiredPrefixes.Any(prefix => permKey.StartsWith(prefix, StringComparison.Ordinal)))
            {
                if (string.IsNullOrWhiteSpace(pk))
                {
                    throw new InvalidOperationException($"Permission '{permKey}' requires product_key due to RequiredProductPrefixes.");
                }
            }

            if (!string.IsNullOrWhiteSpace(pk))
            {
                if (!productStatusByKey.TryGetValue(pk, out var status))
                {
                    throw new InvalidOperationException($"Permission '{permKey}' references missing product '{pk}'.");
                }

                if (status != ProductStatus.Enabled)
                {
                    throw new InvalidOperationException($"Permission '{permKey}' references disabled product '{pk}'.");
                }
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
