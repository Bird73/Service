namespace Birdsoft.Security.Data.EfCore;

using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Data.EfCore.Repositories;
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
        services.AddScoped<ITenantRepository, EfTenantRepository>();
        services.AddScoped<ISubjectRepository, EfSubjectRepository>();
        services.AddScoped<IAuthStateRepository, EfAuthStateRepository>();
        services.AddScoped<IRefreshTokenRepository, EfRefreshTokenRepository>();
        services.AddScoped<IExternalIdentityRepository, EfExternalIdentityRepository>();
        services.AddScoped<ILocalAccountRepository, EfLocalAccountRepository>();

        // Not ideal for large scale (Redis recommended), but keeps interface clean and provider-agnostic.
        services.AddScoped<IAccessTokenDenylistStore, EfAccessTokenDenylistStore>();

        return services;
    }
}
