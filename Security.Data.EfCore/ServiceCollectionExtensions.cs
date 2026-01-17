namespace Birdsoft.Security.Data.EfCore;

using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Repositories;
using Birdsoft.Security.Data.EfCore.Services;
using Birdsoft.Security.Data.EfCore.Stores;
using Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers EF Core implementations for DAL interfaces.
    /// Note: provider (SQLite/PostgreSQL) should be configured in the host via AddDbContext.
    /// </summary>
    public static IServiceCollection AddSecurityEfCoreDataAccess(this IServiceCollection services)
    {
        // Ensure schema exists for hosts/tests that don't eagerly create the database.
        services.AddHostedService<EnsureSecurityDbCreatedHostedService>();

        services.AddScoped<ITenantRepository, EfTenantRepository>();
        services.AddScoped<ISubjectRepository, EfSubjectRepository>();
        services.AddScoped<IAuthStateRepository, EfAuthStateRepository>();
        services.AddScoped<IRefreshTokenRepository, EfRefreshTokenRepository>();
        services.AddScoped<IExternalIdentityRepository, EfExternalIdentityRepository>();
        services.AddScoped<ILocalAccountRepository, EfLocalAccountRepository>();

        // Not ideal for large scale (Redis recommended), but keeps interface clean and provider-agnostic.
        services.AddScoped<IAccessTokenDenylistStore, EfAccessTokenDenylistStore>();

        // Per-tenant OIDC provider persistence.
        services.AddScoped<IOidcProviderRegistry, EfOidcProviderRegistry>();
        services.AddScoped<IOidcProviderService, EfOidcProviderService>();

        services.AddScoped<ISessionStore, EfSessionStore>();
        services.AddScoped<IAuthEventStore, EfAuthEventStore>();

        // Authorization (RBAC) data store (and admin surface)
        services.AddScoped<EfAuthorizationStore>();
        services.AddScoped<IAuthorizationDataStore>(sp => sp.GetRequiredService<EfAuthorizationStore>());
        services.AddScoped<IAuthorizationAdminStore>(sp => sp.GetRequiredService<EfAuthorizationStore>());

        // Entitlements (Products / TenantProducts)
        services.AddScoped<IPermissionCatalogStore, EfPermissionCatalogStore>();
        services.AddScoped<ITenantEntitlementStore, EfTenantEntitlementStore>();

        // Platform token governance (global version / revocation)
        services.AddScoped<IPlatformTokenVersionStore, EfPlatformTokenVersionStore>();

        // Platform admin governance (role assignment + enable/disable)
        services.AddScoped<IPlatformAdminStore, EfPlatformAdminStore>();

        // Commercial governance stores
        services.AddSingleton<IKeyMaterialChangeSignal, KeyMaterialChangeSignal>();
        services.AddScoped<IJwtSigningKeyStore, EfJwtSigningKeyStore>();
        services.AddScoped<IBootstrapKeyStore, EfBootstrapKeyStore>();

        return services;
    }
}
