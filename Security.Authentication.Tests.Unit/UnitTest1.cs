namespace Birdsoft.Security.Authentication.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Identity;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System.Text;
using System.Text.Json;

public sealed class OidcFlowSkeletonTests
{
    [Fact]
    public async Task Oidc_First_Login_Creates_Mapping_And_Issues_Jwt_With_Tenant_And_Subject()
    {
        // Given
        var tenantId = Guid.NewGuid();
        const string provider = "stub";
        const string externalSub = "external-sub-1";
        var services = CreateServices();

        // When
        var (ourSubject, tokenPair) = await SimulateOidcCallbackAsync(services, tenantId, provider, externalSub);

        // Then
        Assert.NotEqual(Guid.Empty, ourSubject);
        Assert.False(string.IsNullOrWhiteSpace(tokenPair.AccessToken));

        var payload = DecodeJwtPayload(tokenPair.AccessToken);
        Assert.Equal(tenantId.ToString(), payload.GetProperty(SecurityClaimTypes.TenantId).GetString());
        Assert.Equal(ourSubject.ToString(), payload.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task Oidc_Same_External_Identity_ReLogin_Reuses_Same_OurSubject()
    {
        // Given
        var tenantId = Guid.NewGuid();
        const string provider = "stub";
        const string externalSub = "external-sub-2";
        var services = CreateServices();

        // When
        var (subject1, _) = await SimulateOidcCallbackAsync(services, tenantId, provider, externalSub);
        var (subject2, _) = await SimulateOidcCallbackAsync(services, tenantId, provider, externalSub);

        // Then
        Assert.Equal(subject1, subject2);
    }

    [Fact]
    public async Task Oidc_Same_ExternalSub_Different_Tenant_Must_Produce_Different_OurSubject()
    {
        // Given
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        const string provider = "stub";
        const string externalSub = "external-sub-3";
        var services = CreateServices();

        // When
        var (subjectA, _) = await SimulateOidcCallbackAsync(services, tenantA, provider, externalSub);
        var (subjectB, _) = await SimulateOidcCallbackAsync(services, tenantB, provider, externalSub);

        // Then
        Assert.NotEqual(subjectA, subjectB);
    }

    [Fact]
    public async Task RefreshToken_Rotation_Revokes_Old_Token()
    {
        // Given
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();
        var services = CreateServices();
        var tokenService = (ITokenService)services.TokenService;
        var first = await tokenService.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);

        // When
        var refreshed = await tokenService.RefreshAsync(first.RefreshToken);
        var reused = await tokenService.RefreshAsync(first.RefreshToken);

        // Then
        Assert.True(refreshed.Succeeded);
        Assert.NotNull(refreshed.Tokens);
        Assert.False(string.IsNullOrWhiteSpace(refreshed.Tokens!.RefreshToken));
        Assert.False(reused.Succeeded);
    }

    private static (object TokenService, IAuthStateService AuthState, IOidcProviderService Oidc, IExternalIdentityStore External, IUserProvisioner Provisioner, IAuthorizationDataStore Authz) CreateServices()
    {
        var jwt = new JwtOptions
        {
            Issuer = "https://security.test",
            Audience = "service",
            SigningKey = "dev-signing-key",
            AccessTokenMinutes = 5,
            RefreshTokenDays = 7,
            ClockSkewSeconds = 30,
        };

        IOptionsMonitor<JwtOptions> monitor = new FakeOptionsMonitor<JwtOptions>(jwt);
        IOptionsMonitor<SecurityEnvironmentOptions> env = new FakeOptionsMonitor<SecurityEnvironmentOptions>(new SecurityEnvironmentOptions { EnvironmentId = "test" });
        IOptionsMonitor<SecuritySafetyOptions> safety = new FakeOptionsMonitor<SecuritySafetyOptions>(new SecuritySafetyOptions { Enabled = false, RequireEnvironmentId = false, EnforceTenantJwtIsolation = false });
        IHostEnvironment hostEnvironment = new FakeHostEnvironment { EnvironmentName = Environments.Development };
        IOptionsMonitor<RefreshTokenHashingOptions> hashing = new FakeOptionsMonitor<RefreshTokenHashingOptions>(new RefreshTokenHashingOptions());
        var keys = new Birdsoft.Security.Authentication.Jwt.DefaultJwtKeyProvider(monitor);
        var sessions = new Birdsoft.Security.Authentication.InMemorySessionStore();
        var tokenService = new Birdsoft.Security.Authentication.InMemoryTokenService(monitor, env, safety, hostEnvironment, hashing, keys, sessions);
        var authState = new Birdsoft.Security.Authentication.InMemoryAuthStateService();
        var oidc = new Birdsoft.Security.Authentication.InMemoryOidcProviderService();
        var external = new Birdsoft.Security.Authentication.InMemoryExternalIdentityStore();
        var provisioner = new Birdsoft.Security.Authentication.InMemoryUserProvisioner();
        var authz = new Birdsoft.Security.Authentication.InMemoryAuthorizationDataStore();
        return (tokenService, authState, oidc, external, provisioner, authz);
    }

    private static async Task<(Guid ourSubject, Birdsoft.Security.Abstractions.TokenPair tokenPair)> SimulateOidcCallbackAsync(
        (object TokenService, IAuthStateService AuthState, IOidcProviderService Oidc, IExternalIdentityStore External, IUserProvisioner Provisioner, IAuthorizationDataStore Authz) services,
        Guid tenantId,
        string provider,
        string externalSub)
    {
        // create state and attach context
        var stateInfo = await services.AuthState.CreateStateAsync(tenantId);
        await services.AuthState.TryAttachOidcContextAsync(stateInfo.State, codeVerifier: "cv", nonce: "nonce");
        var ctx = await services.AuthState.ConsumeStateAsync(stateInfo.State);
        Assert.NotNull(ctx);

        // exchange code
        var userInfo = await services.Oidc.ExchangeCodeAsync(tenantId, provider, externalSub, ctx!);
        var key = new ExternalIdentityKey(tenantId, provider, userInfo.Issuer, userInfo.ProviderSub);
        var mapping = await services.External.FindMappingAsync(key);

        var ourSubject = mapping?.OurSubject
            ?? await services.Provisioner.ProvisionAsync(tenantId, key, userInfo);

        if (mapping is null)
        {
            await services.External.CreateMappingAsync(new ExternalIdentityMapping(
                tenantId,
                ourSubject,
                provider,
                userInfo.Issuer,
                userInfo.ProviderSub,
                DateTimeOffset.UtcNow));
        }

        var roles = await services.Authz.GetRolesAsync(tenantId, ourSubject);
        var scopes = await services.Authz.GetScopesAsync(tenantId, ourSubject);
        var tokenPair = await ((ITokenService)services.TokenService).GenerateTokensAsync(tenantId, ourSubject, roles, scopes);
        return (ourSubject, tokenPair);
    }

    private static JsonElement DecodeJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.True(parts.Length == 3);
        var json = Encoding.UTF8.GetString(DecodeBase64Url(parts[1]));
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static byte[] DecodeBase64Url(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        var padding = 4 - (padded.Length % 4);
        if (padding is > 0 and < 4)
        {
            padded += new string('=', padding);
        }

        return Convert.FromBase64String(padded);
    }

    private sealed class FakeOptionsMonitor<T>(T current) : IOptionsMonitor<T>
        where T : class
    {
        public T CurrentValue => current;
        public T Get(string? name) => current;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class FakeHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
