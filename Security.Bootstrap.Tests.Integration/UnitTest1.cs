extern alias Authn;
extern alias Authz;

namespace Birdsoft.Security.Bootstrap.Tests.Integration;

using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Infrastructure.Logging.Abstractions;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit.Sdk;

public sealed class DefaultAdminBootstrapIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static readonly Guid DefaultAdminSubject = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    private sealed class UnhandledExceptionCapture
    {
        private readonly object _gate = new();
        public Exception? LastException { get; private set; }
        public string? LastMessageTemplate { get; private set; }

        public void Capture(Exception? exception, string messageTemplate)
        {
            lock (_gate)
            {
                LastException = exception;
                LastMessageTemplate = messageTemplate;
            }
        }
    }

    private sealed class TestAppLogger<T>(UnhandledExceptionCapture capture) : IAppLogger<T>
    {
        public bool IsEnabled(LogLevel level) => true;

        public void Log(LogLevel level, Exception? exception, string messageTemplate, params object?[] args)
        {
            if (level >= LogLevel.Error)
            {
                capture.Capture(exception, messageTemplate);
            }
        }
    }

    private sealed class AuthnApiFactory(string connectionString, string jwtIssuer, string jwtAudience, string jwtSigningKey) : WebApplicationFactory<Authn::Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");

            builder.ConfigureAppConfiguration((context, config) =>
            {
                var dict = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SecurityDb"] = connectionString,

                    ["Bootstrap:Enabled"] = "true",
                    ["Bootstrap:Key"] = "test-bootstrap-key",

                    [$"{JwtOptions.SectionName}:Issuer"] = jwtIssuer,
                    [$"{JwtOptions.SectionName}:Audience"] = jwtAudience,
                    [$"{JwtOptions.SectionName}:SigningKey"] = jwtSigningKey,
                    [$"{JwtOptions.SectionName}:SigningAlgorithm"] = "HS256",
                    [$"{JwtOptions.SectionName}:AccessTokenMinutes"] = "5",
                    [$"{JwtOptions.SectionName}:RefreshTokenDays"] = "7",
                    [$"{JwtOptions.SectionName}:ClockSkewSeconds"] = "30",

                    ["Security:RefreshTokenHashing:Pepper"] = "bootstrap-tests-pepper",

                    ["Security:Environment:EnvironmentId"] = "test",
                    [$"{SecuritySafetyOptions.SectionName}:Enabled"] = "false",
                    [$"{SecuritySafetyOptions.SectionName}:RequireEnvironmentId"] = "false",
                    [$"{SecuritySafetyOptions.SectionName}:EnforceTenantJwtIsolation"] = "false",

                    // Password login is in-memory (option-driven). Bootstrap seeds the subject in DB,
                    // and we keep the same OurSubject here so login produces a token for that subject.
                    [$"{PasswordLoginOptions.SectionName}:Enabled"] = "true",
                    [$"{PasswordLoginOptions.SectionName}:Users:0:Username"] = "admin",
                    [$"{PasswordLoginOptions.SectionName}:Users:0:Password"] = "Passw0rd!",
                    [$"{PasswordLoginOptions.SectionName}:Users:0:OurSubject"] = DefaultAdminBootstrapIntegrationTests.DefaultAdminSubject.ToString(),
                };

                config.AddInMemoryCollection(dict);
            });

            builder.ConfigureServices(services =>
            {
                // Surface unhandled exceptions in tests even if the API returns a generic internal_error.
                services.AddSingleton<UnhandledExceptionCapture>();
                services.RemoveAll(typeof(IAppLogger<>));
                services.AddTransient(typeof(IAppLogger<>), typeof(TestAppLogger<>));

                // Force EF-backed stack even if Program.cs computed useEf=false before WebApplicationFactory
                // configuration is applied.
                services.RemoveAll<SecurityDbContext>();
                services.RemoveAll<DbContextOptions<SecurityDbContext>>();

                services.RemoveAll<IAuthEventStore>();
                services.RemoveAll<IAuthStateService>();
                services.RemoveAll<IExternalIdentityStore>();
                services.RemoveAll<ITenantRepository>();
                services.RemoveAll<ISubjectRepository>();
                services.RemoveAll<ISessionStore>();
                services.RemoveAll<ITokenService>();
                services.RemoveAll<Authn::Birdsoft.Security.Authentication.InMemoryTokenService>();

                services.RemoveAll<IAuthStateRepository>();
                services.RemoveAll<IRefreshTokenRepository>();
                services.RemoveAll<IExternalIdentityRepository>();
                services.RemoveAll<ILocalAccountRepository>();
                services.RemoveAll<IAccessTokenDenylistStore>();
                services.RemoveAll<IOidcProviderRegistry>();
                services.RemoveAll<IOidcProviderService>();

                services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(connectionString));
                services.AddSecurityEfCoreDataAccess();

                services.AddScoped<IAuthStateService, Authn::Birdsoft.Security.Authentication.Persistence.RepositoryAuthStateService>();
                services.AddScoped<IExternalIdentityStore, Authn::Birdsoft.Security.Authentication.Persistence.ExternalIdentityStoreFromRepository>();
                services.AddScoped<ITokenService, Authn::Birdsoft.Security.Authentication.Persistence.RepositoryTokenService>();
            });
        }
    }

    private sealed class AuthzApiFactory(string connectionString, string jwtIssuer, string jwtAudience, string jwtSigningKey) : WebApplicationFactory<Authz::Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");

            builder.ConfigureAppConfiguration((context, config) =>
            {
                var dict = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SecurityDb"] = connectionString,

                    [$"{JwtOptions.SectionName}:Issuer"] = jwtIssuer,
                    [$"{JwtOptions.SectionName}:Audience"] = jwtAudience,
                    [$"{JwtOptions.SectionName}:SigningKey"] = jwtSigningKey,
                    [$"{JwtOptions.SectionName}:SigningAlgorithm"] = "HS256",
                    [$"{JwtOptions.SectionName}:ClockSkewSeconds"] = "30",

                    ["Security:Environment:EnvironmentId"] = "test",
                    [$"{SecuritySafetyOptions.SectionName}:Enabled"] = "false",
                    [$"{SecuritySafetyOptions.SectionName}:RequireEnvironmentId"] = "false",
                    [$"{SecuritySafetyOptions.SectionName}:EnforceTenantJwtIsolation"] = "false",
                };

                config.AddInMemoryCollection(dict);
            });

            builder.ConfigureServices(services =>
            {
                // Force EF-backed stack even if Program.cs computed useEf=false before WebApplicationFactory
                // configuration is applied.
                services.RemoveAll<SecurityDbContext>();
                services.RemoveAll<DbContextOptions<SecurityDbContext>>();

                services.RemoveAll<ITenantRepository>();
                services.RemoveAll<ISubjectRepository>();
                services.RemoveAll<ISessionStore>();
                services.RemoveAll<IAuthEventStore>();
                services.RemoveAll<IAuthorizationDataStore>();
                services.RemoveAll<IPermissionCatalogStore>();
                services.RemoveAll<ITenantEntitlementStore>();

                services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(connectionString));
                services.AddSecurityEfCoreDataAccess();
            });
        }
    }

    private static string CreateTempSqliteDbPath()
    {
        var root = Path.Combine(Path.GetTempPath(), "Birdsoft.Security.Bootstrap.Tests", "db");
        Directory.CreateDirectory(root);
        return Path.Combine(root, $"security-{Guid.NewGuid():N}.sqlite");
    }

    private sealed record BootstrapRequest(
        Guid? TenantId,
        string? TenantName,
        Guid? OurSubject,
        string Username,
        string Password,
        string? ProductKey,
        string? PermissionKey);

    private sealed record BootstrapResult(Guid TenantId, Guid OurSubject, string Username, string ProductKey, string PermissionKey);

    private sealed record TenantSetUserPermissionRequest(string PermissionKey, string? Reason);

    [Fact]
    public async Task EmptyDb_Bootstrap_DefaultAdmin_Can_Login_And_Manage_Tenant_Permissions()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            var authnClient = authnFactory.CreateClient();

            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "bootstrap-tenant",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");

            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            if (bootstrapRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await bootstrapRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/bootstrap failed: {(int)bootstrapRes.StatusCode} {bootstrapRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var bootstrapBody = await bootstrapRes.Content.ReadFromJsonAsync<ApiResponse<BootstrapResult>>(JsonOptions);
            Assert.NotNull(bootstrapBody);
            Assert.True(bootstrapBody!.Success);
            Assert.NotNull(bootstrapBody.Data);

            var tenantId = bootstrapBody.Data!.TenantId;
            var ourSubject = bootstrapBody.Data.OurSubject;
            Assert.NotEqual(Guid.Empty, tenantId);
            Assert.NotEqual(Guid.Empty, ourSubject);

            // Login via password (AuthN) to get a tenant token with security.admin scope.
            using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "admin", Password: "Passw0rd!")),
            };
            loginReq.Headers.Add("X-Tenant-Id", tenantId.ToString());

            var loginRes = await authnClient.SendAsync(loginReq);
            if (loginRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await loginRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/auth/password/login failed: {(int)loginRes.StatusCode} {loginRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var loginBody = await loginRes.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(loginBody);
            Assert.True(loginBody!.Success);
            Assert.NotNull(loginBody.Data);
            Assert.Equal("success", loginBody.Data!.Status);
            Assert.NotNull(loginBody.Data.Tokens);

            var accessToken = loginBody.Data.Tokens!.AccessToken;
            Assert.False(string.IsNullOrWhiteSpace(accessToken));

            // Call tenant admin surface (AuthZ) using the minted token.
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);
            var authzClient = authzFactory.CreateClient();

            using var listReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/permissions");
            listReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var listRes = await authzClient.SendAsync(listReq);
            Assert.Equal(HttpStatusCode.OK, listRes.StatusCode);

            // Grant a permission to the default admin (exercise management path).
            using var grantReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenant/users/{ourSubject}/permissions")
            {
                Content = JsonContent.Create(new TenantSetUserPermissionRequest(PermissionKey: "security.manage", Reason: "bootstrap-test")),
            };
            grantReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var grantRes = await authzClient.SendAsync(grantReq);
            Assert.Equal(HttpStatusCode.OK, grantRes.StatusCode);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }
}
