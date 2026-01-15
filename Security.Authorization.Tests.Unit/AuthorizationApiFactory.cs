namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Infrastructure.Logging.Abstractions;
using Birdsoft.Security.Authorization.Api.Observability.Logging;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Data.EfCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public sealed class AuthorizationApiFactory : WebApplicationFactory<Program>
{
    private readonly Overrides _overrides;

    public string AuthErrorLogRootDirectory { get; }

    public AuthorizationApiFactory(Overrides? overrides = null)
    {
        _overrides = overrides ?? new Overrides();

        AuthErrorLogRootDirectory = _overrides.AuthErrorLogRootDirectory
            ?? Path.Combine(Path.GetTempPath(), "Birdsoft.Security.Authorization.Tests", "auth-error-logs", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(AuthErrorLogRootDirectory);
    }

    public sealed class Overrides
    {
        public string? SecurityDbConnectionString { get; init; }

        public string? AuthErrorLogRootDirectory { get; init; }

        public IAuthEventStore? AuthEvents { get; init; }

        public string JwtIssuer { get; init; } = "https://security.authz.test";
        public string JwtAudience { get; init; } = "service";
        public string JwtSigningKey { get; init; } = "dev-signing-key-123456789012345678901234567890";
        public string JwtSigningAlgorithm { get; init; } = "HS256";
        public int ClockSkewSeconds { get; init; } = 30;

        public string EnvironmentId { get; init; } = "test";
        public bool SafetyEnabled { get; init; } = false;

        public IReadOnlyDictionary<string, string?>? ExtraConfiguration { get; init; }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureAppConfiguration((context, config) =>
        {
            var dict = new Dictionary<string, string?>
            {
                ["ConnectionStrings:SecurityDb"] = _overrides.SecurityDbConnectionString,

                [$"{JwtOptions.SectionName}:Issuer"] = _overrides.JwtIssuer,
                [$"{JwtOptions.SectionName}:Audience"] = _overrides.JwtAudience,
                [$"{JwtOptions.SectionName}:SigningKey"] = _overrides.JwtSigningKey,
                [$"{JwtOptions.SectionName}:SigningAlgorithm"] = _overrides.JwtSigningAlgorithm,
                [$"{JwtOptions.SectionName}:ClockSkewSeconds"] = _overrides.ClockSkewSeconds.ToString(),

                [$"{SecurityEnvironmentOptions.SectionName}:EnvironmentId"] = _overrides.EnvironmentId,

                [$"{SecuritySafetyOptions.SectionName}:Enabled"] = _overrides.SafetyEnabled.ToString(),
                [$"{SecuritySafetyOptions.SectionName}:RequireEnvironmentId"] = "false",
                [$"{SecuritySafetyOptions.SectionName}:EnforceTenantJwtIsolation"] = "false",
            };

            if (_overrides.ExtraConfiguration is not null)
            {
                foreach (var kv in _overrides.ExtraConfiguration)
                {
                    dict[kv.Key] = kv.Value;
                }
            }

            config.AddInMemoryCollection(dict);
        });

        builder.ConfigureServices(services =>
        {
            // Make unhandled-exception error logs discoverable in tests.
            services.RemoveAll<ILogFilePathProvider>();
            services.AddSingleton<ILogFilePathProvider>(_ => new AuthErrorLogFilePathProvider(AuthErrorLogRootDirectory));

            // Also capture unhandled exceptions in-memory so tests can surface the root cause even if file logging is async.
            services.AddSingleton<UnhandledExceptionCapture>();
            services.RemoveAll(typeof(IAppLogger<>));
            services.AddTransient(typeof(IAppLogger<>), typeof(TestAppLogger<>));

            if (string.IsNullOrWhiteSpace(_overrides.SecurityDbConnectionString))
            {
                return;
            }

            // Ensure tests always run with EF-backed stores, regardless of Program.cs' useEf switch.
            services.RemoveAll<SecurityDbContext>();
            services.RemoveAll<DbContextOptions<SecurityDbContext>>();

            services.RemoveAll<Birdsoft.Security.Abstractions.Repositories.ITenantRepository>();
            services.RemoveAll<Birdsoft.Security.Abstractions.Repositories.ISubjectRepository>();
            services.RemoveAll<Birdsoft.Security.Abstractions.Stores.ISessionStore>();
            services.RemoveAll<Birdsoft.Security.Abstractions.Stores.IAuthEventStore>();

            services.RemoveAll<Birdsoft.Security.Abstractions.Stores.IAuthorizationDataStore>();
            services.RemoveAll<Birdsoft.Security.Abstractions.Stores.IPermissionCatalogStore>();
            services.RemoveAll<Birdsoft.Security.Abstractions.Stores.ITenantEntitlementStore>();

            services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(_overrides.SecurityDbConnectionString));
            services.AddSecurityEfCoreDataAccess();

            if (_overrides.AuthEvents is not null)
            {
                services.RemoveAll<IAuthEventStore>();
                services.AddSingleton(_overrides.AuthEvents);
            }
        });
    }
}
