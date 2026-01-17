namespace Birdsoft.Security.Authorization.Api.Authz;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authorization.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

public sealed class AuthorizationGuardrailsHostedService : IHostedService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<AuthorizationGuardrailsHostedService> _logger;

    public AuthorizationGuardrailsHostedService(IServiceProvider services, ILogger<AuthorizationGuardrailsHostedService> logger)
    {
        _services = services;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _ = cancellationToken;

        using var scope = _services.CreateScope();

        var opts = scope.ServiceProvider.GetRequiredService<IOptionsMonitor<SecurityAuthorizationOptions>>().CurrentValue;

        if (opts.UnsafeDevMode)
        {
            _logger.LogWarning("Security:Authorization:UnsafeDevMode is ENABLED. Authorization guardrails are relaxed. Do NOT use this setting in Production/Staging.");
            return Task.CompletedTask;
        }

        var catalog = scope.ServiceProvider.GetService<IPermissionCatalogStore>();
        var entitlements = scope.ServiceProvider.GetService<ITenantEntitlementStore>();

        if (catalog is NullPermissionCatalogStore)
        {
            throw new InvalidOperationException("Unsafe authorization configuration: NullPermissionCatalogStore is not allowed unless Security:Authorization:UnsafeDevMode=true.");
        }

        if (entitlements is AllowAllTenantEntitlementStore)
        {
            throw new InvalidOperationException("Unsafe authorization configuration: AllowAllTenantEntitlementStore is not allowed unless Security:Authorization:UnsafeDevMode=true.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _ = cancellationToken;
        return Task.CompletedTask;
    }
}
