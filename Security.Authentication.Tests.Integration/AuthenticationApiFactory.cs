namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Security.Abstractions.Mfa;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authentication.Persistence;
using Birdsoft.Security.Data.EfCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public sealed class AuthenticationApiFactory : WebApplicationFactory<Program>
{
    private readonly Overrides _overrides;

    public AuthenticationApiFactory(Overrides? overrides = null)
    {
        _overrides = overrides ?? new Overrides();
    }

    public sealed class Overrides
    {
        public Guid TenantId { get; init; } = Guid.Parse("11111111-1111-1111-1111-111111111111");

        public string? SecurityDbConnectionString { get; init; }

        public ITenantRepository? Tenants { get; init; }
        public ISubjectRepository? Subjects { get; init; }
        public IAuthorizationDataStore? Authz { get; init; }
        public IAuthEventStore? AuthEvents { get; init; }
        public IPasswordAuthenticator? Password { get; init; }
        public IBruteForceProtection? BruteForce { get; init; }
        public IMfaPolicyProvider? MfaPolicy { get; init; }
        public IMfaChallengeStore? MfaChallenges { get; init; }

        public bool AllowSkipOnMfaProviderFailure { get; init; } = false;

        public bool EnableTestEndpoints { get; init; } = false;

        public string JwtIssuer { get; init; } = "https://security.test";
        public string JwtAudience { get; init; } = "service";
        public string JwtSigningKey { get; init; } = "dev-signing-key-123456789012345678901234567890";
        public int AccessTokenMinutes { get; init; } = 5;
        public int RefreshTokenDays { get; init; } = 7;
        public int ClockSkewSeconds { get; init; } = 30;

        public string RefreshTokenPepper { get; init; } = "integration-test-pepper";

        public string EnvironmentId { get; init; } = "test";
        public bool SafetyEnabled { get; init; } = false;

        /// <summary>
        /// Extra configuration entries to inject for a test.
        /// Useful for complex option binding like JwtOptions.KeyRing.Keys[n].*
        /// </summary>
        public IReadOnlyDictionary<string, string?>? ExtraConfiguration { get; init; }
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
                [$"{JwtOptions.SectionName}:AccessTokenMinutes"] = _overrides.AccessTokenMinutes.ToString(),
                [$"{JwtOptions.SectionName}:RefreshTokenDays"] = _overrides.RefreshTokenDays.ToString(),
                [$"{JwtOptions.SectionName}:ClockSkewSeconds"] = _overrides.ClockSkewSeconds.ToString(),

                [$"{RefreshTokenHashingOptions.SectionName}:Pepper"] = _overrides.RefreshTokenPepper,

                [$"{SecurityEnvironmentOptions.SectionName}:EnvironmentId"] = _overrides.EnvironmentId,

                [$"{SecuritySafetyOptions.SectionName}:Enabled"] = _overrides.SafetyEnabled.ToString(),
                [$"{SecuritySafetyOptions.SectionName}:RequireEnvironmentId"] = "false",
                [$"{SecuritySafetyOptions.SectionName}:EnforceTenantJwtIsolation"] = "false",

                [$"{MfaOptions.SectionName}:AllowSkipOnProviderFailure"] = _overrides.AllowSkipOnMfaProviderFailure.ToString(),
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
            if (!string.IsNullOrWhiteSpace(_overrides.SecurityDbConnectionString))
            {
                // Force EF-backed stack for integration tests that need refresh-token persistence.
                services.RemoveAll<SecurityDbContext>();
                services.RemoveAll<DbContextOptions<SecurityDbContext>>();

                services.RemoveAll<IAuthEventStore>();
                services.RemoveAll<IAuthStateService>();
                services.RemoveAll<IExternalIdentityStore>();
                services.RemoveAll<ITenantRepository>();
                services.RemoveAll<ISubjectRepository>();
                services.RemoveAll<ISessionStore>();
                services.RemoveAll<ITokenService>();

                // Program.cs registers InMemoryTokenService as a concrete singleton in non-EF mode.
                // When integration tests force EF-backed services, that singleton would end up
                // consuming scoped EF services (via ISessionStore), which fails DI validation.
                services.RemoveAll<Birdsoft.Security.Authentication.InMemoryTokenService>();

                services.RemoveAll<IAuthStateRepository>();
                services.RemoveAll<IRefreshTokenRepository>();
                services.RemoveAll<IExternalIdentityRepository>();
                services.RemoveAll<ILocalAccountRepository>();
                services.RemoveAll<IAccessTokenDenylistStore>();
                services.RemoveAll<IOidcProviderRegistry>();
                services.RemoveAll<IOidcProviderService>();

                services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(_overrides.SecurityDbConnectionString));
                services.AddSecurityEfCoreDataAccess();

                services.AddScoped<IAuthStateService, RepositoryAuthStateService>();
                services.AddScoped<IExternalIdentityStore, ExternalIdentityStoreFromRepository>();
                services.AddScoped<ITokenService, RepositoryTokenService>();
            }

            if (_overrides.AuthEvents is not null)
            {
                services.RemoveAll<IAuthEventStore>();
                services.AddSingleton(_overrides.AuthEvents);
            }

            // Replace dependencies so each test can deterministically drive endpoint branches.
            if (_overrides.Tenants is not null)
            {
                services.RemoveAll<ITenantRepository>();
                services.AddSingleton(_overrides.Tenants);
            }

            if (_overrides.Subjects is not null)
            {
                services.RemoveAll<ISubjectRepository>();
                services.AddSingleton(_overrides.Subjects);
            }

            if (_overrides.Authz is not null)
            {
                services.RemoveAll<IAuthorizationDataStore>();
                services.RemoveAll<IAuthorizationAdminStore>();

                services.AddSingleton<IAuthorizationDataStore>(_overrides.Authz);
                if (_overrides.Authz is IAuthorizationAdminStore admin)
                {
                    services.AddSingleton<IAuthorizationAdminStore>(admin);
                }
            }

            if (_overrides.Password is not null)
            {
                services.RemoveAll<IPasswordAuthenticator>();
                services.AddSingleton(_overrides.Password);
            }

            if (_overrides.BruteForce is not null)
            {
                services.RemoveAll<IBruteForceProtection>();
                services.AddSingleton(_overrides.BruteForce);
            }

            if (_overrides.MfaPolicy is not null)
            {
                services.RemoveAll<IMfaPolicyProvider>();
                services.AddSingleton(_overrides.MfaPolicy);
            }

            if (_overrides.MfaChallenges is not null)
            {
                services.RemoveAll<IMfaChallengeStore>();
                services.AddSingleton(_overrides.MfaChallenges);
            }
        });
    }
}

public sealed class StubTenantRepository(TenantDto? tenant) : ITenantRepository
{
    public Task<TenantDto?> FindAsync(Guid tenantId, CancellationToken cancellationToken = default)
        => Task.FromResult(tenant);

    public Task<TenantDto> CreateAsync(Guid tenantId, string name, CancellationToken cancellationToken = default)
        => Task.FromResult(new TenantDto { TenantId = tenantId, Name = name, Status = TenantStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow });

    public Task<int> IncrementTokenVersionAsync(Guid tenantId, CancellationToken cancellationToken = default)
        => Task.FromResult(1);

    public Task<int> UpdateStatusAsync(Guid tenantId, TenantStatus status, CancellationToken cancellationToken = default)
        => Task.FromResult(1);
}

public sealed class StubSubjectRepository(SubjectDto? findResult, Func<Guid, Guid, SubjectDto>? create = null) : ISubjectRepository
{
    public Task<SubjectDto?> FindAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        => Task.FromResult(findResult);

    public Task<SubjectDto> CreateAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        => Task.FromResult(create?.Invoke(tenantId, ourSubject)
            ?? new SubjectDto { TenantId = tenantId, OurSubject = ourSubject, Status = UserStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow });

    public Task<int> UpdateTokenVersionAsync(Guid tenantId, Guid ourSubject, int newVersion, CancellationToken cancellationToken = default)
        => Task.FromResult(1);

    public Task<int> IncrementTokenVersionAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        => Task.FromResult(1);

    public Task<int> UpdateStatusAsync(Guid tenantId, Guid ourSubject, UserStatus status, CancellationToken cancellationToken = default)
        => Task.FromResult(1);
}

public sealed class StubAuthorizationDataStore(string[]? roles = null, string[]? scopes = null, string[]? permissions = null) : IAuthorizationDataStore
{
    private readonly IReadOnlyList<string> _roles = roles ?? [];
    private readonly IReadOnlyList<string> _scopes = scopes ?? [];
    private readonly IReadOnlyList<string> _permissions = permissions ?? [];

    public ValueTask<IReadOnlyList<string>> GetRolesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_roles);

    public ValueTask<IReadOnlyList<string>> GetScopesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_scopes);

    public ValueTask<IReadOnlyList<string>> GetPermissionsAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_permissions);
}

public sealed class StubPasswordAuthenticator(PasswordAuthResult result) : IPasswordAuthenticator
{
    public ValueTask<PasswordAuthResult> AuthenticateAsync(Guid tenantId, string username, string password, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(result);
}

public sealed class StubBruteForceProtection(BruteForceDecision decision) : IBruteForceProtection
{
    public ValueTask<BruteForceDecision> CheckAsync(Guid tenantId, string username, string ip, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(decision);

    public ValueTask RecordFailureAsync(Guid tenantId, string username, string ip, string reason, CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;

    public ValueTask RecordSuccessAsync(Guid tenantId, string username, string ip, CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;
}

public sealed class StubMfaPolicyProvider(MfaPolicy policy) : IMfaPolicyProvider
{
    public Task<MfaPolicy> GetPolicyAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        => Task.FromResult(policy);
}

public sealed class StubMfaChallengeStore(MfaChallenge challenge, bool throwOnCreate = false) : IMfaChallengeStore
{
    public Task<MfaChallenge> CreateAsync(Guid tenantId, Guid ourSubject, TimeSpan ttl, string? providerHint = null, CancellationToken cancellationToken = default)
        => throwOnCreate ? throw new InvalidOperationException("mfa provider down") : Task.FromResult(challenge with { TenantId = tenantId, OurSubject = ourSubject });

    public Task<MfaChallenge?> FindAsync(Guid challengeId, CancellationToken cancellationToken = default)
        => Task.FromResult<MfaChallenge?>(challengeId == challenge.ChallengeId ? challenge : null);

    public Task<bool> ConsumeAsync(Guid challengeId, CancellationToken cancellationToken = default)
        => Task.FromResult(true);
}
