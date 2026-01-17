namespace Birdsoft.Security.Authorization.Tests.Integration;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Data.EfCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public sealed class AuthorizationApiFactory : WebApplicationFactory<global::Program>
{
    private readonly Overrides _overrides;

    public AuthorizationApiFactory(Overrides? overrides = null)
    {
        _overrides = overrides ?? new Overrides();
    }

    public sealed class Overrides
    {
        public string? SecurityDbConnectionString { get; init; }

        public bool EnableTestEndpoints { get; init; } = false;

        public string JwtIssuer { get; init; } = "https://security.test";
        public string JwtAudience { get; init; } = "service";
        public string JwtSigningKey { get; init; } = "dev-signing-key-123456789012345678901234567890";
        public int ClockSkewSeconds { get; init; } = 30;

        public string EnvironmentId { get; init; } = "test";
        public bool SafetyEnabled { get; init; } = false;

        public string[]? RequiredProductPrefixes { get; init; }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureAppConfiguration((context, config) =>
        {
            var dict = new Dictionary<string, string?>
            {
                ["Logging:LogLevel:Default"] = "Warning",
                ["Logging:LogLevel:Microsoft"] = "Warning",
                ["Logging:LogLevel:System"] = "Warning",
                ["Logging:LogLevel:Microsoft.EntityFrameworkCore.Database.Command"] = "Warning",
                ["Logging:LogLevel:Microsoft.AspNetCore.HttpsPolicy"] = "Error",

                ["ConnectionStrings:SecurityDb"] = _overrides.SecurityDbConnectionString,
                ["TestEndpoints:Enabled"] = _overrides.EnableTestEndpoints.ToString(),

                [$"{JwtOptions.SectionName}:Issuer"] = _overrides.JwtIssuer,
                [$"{JwtOptions.SectionName}:Audience"] = _overrides.JwtAudience,
                [$"{JwtOptions.SectionName}:SigningKey"] = _overrides.JwtSigningKey,
                [$"{JwtOptions.SectionName}:ClockSkewSeconds"] = _overrides.ClockSkewSeconds.ToString(),

                [$"{SecurityEnvironmentOptions.SectionName}:EnvironmentId"] = _overrides.EnvironmentId,

                [$"{SecuritySafetyOptions.SectionName}:Enabled"] = _overrides.SafetyEnabled.ToString(),
                [$"{SecuritySafetyOptions.SectionName}:RequireEnvironmentId"] = "false",
                [$"{SecuritySafetyOptions.SectionName}:EnforceTenantJwtIsolation"] = "false",
            };

            if (_overrides.RequiredProductPrefixes is not null)
            {
                for (var i = 0; i < _overrides.RequiredProductPrefixes.Length; i++)
                {
                    dict[$"{SecurityAuthorizationOptions.SectionName}:RequiredProductPrefixes:{i}"] = _overrides.RequiredProductPrefixes[i];
                }
            }

            config.AddInMemoryCollection(dict);
        });

        builder.ConfigureServices(services =>
        {
            if (!string.IsNullOrWhiteSpace(_overrides.SecurityDbConnectionString))
            {
                // WebApplicationFactory can apply configuration overrides after Program.cs decides
                // whether EF is enabled. Force EF-backed wiring for startup governance tests.
                services.RemoveAll<SecurityDbContext>();
                services.RemoveAll<DbContextOptions<SecurityDbContext>>();

                services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(_overrides.SecurityDbConnectionString));
                services.AddSecurityEfCoreDataAccess();
            }
        });
    }
}
