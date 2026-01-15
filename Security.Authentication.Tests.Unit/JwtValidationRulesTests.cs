namespace Birdsoft.Security.Authentication.Tests.Unit;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authentication.Jwt;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

public sealed class JwtValidationRulesTests
{
    [Fact]
    public async Task ValidateAccessToken_Fails_When_Issuer_Does_Not_Match_Options()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var issuerA = "https://security.test";
        var issuerB = "https://security.other";

        var issuedByA = CreateTokenService(issuer: issuerA, audience: "service", signingKey: "unit-test-key", kid: "k1");
        var validatedByB = CreateTokenService(issuer: issuerB, audience: "service", signingKey: "unit-test-key", kid: "k1");

        var pair = await issuedByA.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        var result = await validatedByB.ValidateAccessTokenAsync(pair.AccessToken);

        Assert.False(result.Succeeded);
        Assert.Equal("invalid_issuer", result.ErrorCode);
    }

    [Fact]
    public async Task ValidateAccessToken_Fails_When_Audience_Does_Not_Contain_Configured_Audience()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var issuedByA = CreateTokenService(issuer: "https://security.test", audience: "service", signingKey: "unit-test-key", kid: "k1");
        var validatedByB = CreateTokenService(issuer: "https://security.test", audience: "different-audience", signingKey: "unit-test-key", kid: "k1");

        var pair = await issuedByA.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        var result = await validatedByB.ValidateAccessTokenAsync(pair.AccessToken);

        Assert.False(result.Succeeded);
        Assert.Equal("invalid_audience", result.ErrorCode);
    }

    private static ITokenService CreateTokenService(string issuer, string audience, string signingKey, string kid)
    {
        // Use HS256 so two services can share the same verification key deterministically.
        var jwt = new JwtOptions
        {
            Issuer = issuer,
            Audience = audience,
            SigningAlgorithm = "HS256",
            SigningKey = signingKey,
            Kid = kid,
            AccessTokenMinutes = 5,
            RefreshTokenDays = 7,
            ClockSkewSeconds = 30,
        };

        IOptionsMonitor<JwtOptions> monitor = new FakeOptionsMonitor<JwtOptions>(jwt);
        IOptionsMonitor<SecurityEnvironmentOptions> env = new FakeOptionsMonitor<SecurityEnvironmentOptions>(new SecurityEnvironmentOptions { EnvironmentId = "test" });
        IOptionsMonitor<SecuritySafetyOptions> safety = new FakeOptionsMonitor<SecuritySafetyOptions>(new SecuritySafetyOptions { Enabled = false, RequireEnvironmentId = false, EnforceTenantJwtIsolation = false });
        IOptionsMonitor<RefreshTokenHashingOptions> hashing = new FakeOptionsMonitor<RefreshTokenHashingOptions>(new RefreshTokenHashingOptions { Pepper = "unit-test-pepper" });
        IHostEnvironment hostEnvironment = new FakeHostEnvironment { EnvironmentName = Environments.Development };
        IJwtKeyProvider keys = new DefaultJwtKeyProvider(monitor);
        ISessionStore sessions = new InMemorySessionStore();

        return new InMemoryTokenService(monitor, env, safety, hostEnvironment, hashing, keys, sessions);
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
