namespace Birdsoft.Security.Authentication.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authentication.Jwt;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System.Text.Json;

public sealed class JwtSpecTokenClaimsTests
{
    [Fact]
    public async Task GenerateTokens_Issues_AccessToken_With_Required_Claims_And_Subject_Semantics()
    {
        // Spec: JwtSpec.md required claims + sub == our_subject + includes session_id.
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var tokenService = CreateTokenService(
            issuer: "https://security.test",
            audience: "service",
            signingAlgorithm: "HS256",
            signingKey: "unit-test-signing-key",
            kid: "k1");

        var pair = await tokenService.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);

        Assert.False(string.IsNullOrWhiteSpace(pair.AccessToken));
        var payload = JwtTestHelpers.DecodeJwtPayload(pair.AccessToken);

        // Required claims.
        var iss = payload.GetProperty("iss").GetString();
        var aud = payload.GetProperty("aud").GetString();
        Assert.True(
            string.Equals(iss, "https://security.test", StringComparison.Ordinal)
            || string.Equals(iss, "https://security.test/env/test", StringComparison.Ordinal));
        Assert.True(
            string.Equals(aud, "service", StringComparison.Ordinal)
            || string.Equals(aud, "service/env/test", StringComparison.Ordinal));
        Assert.True(payload.TryGetProperty("exp", out var exp) && exp.ValueKind == JsonValueKind.Number);
        Assert.True(payload.TryGetProperty("iat", out var iat) && iat.ValueKind == JsonValueKind.Number);
        Assert.True(payload.TryGetProperty("nbf", out var nbf) && nbf.ValueKind == JsonValueKind.Number);
        Assert.False(string.IsNullOrWhiteSpace(payload.GetProperty(SecurityClaimTypes.Jti).GetString()));

        // tenant_id, sub, session_id.
        Assert.Equal(tenantId.ToString(), payload.GetProperty(SecurityClaimTypes.TenantId).GetString());
        Assert.Equal(ourSubject.ToString(), payload.GetProperty("sub").GetString());
        Assert.False(string.IsNullOrWhiteSpace(payload.GetProperty(SecurityClaimTypes.SessionId).GetString()));

        // Subject semantics: sub == our_subject.
        Assert.Equal(
            payload.GetProperty("sub").GetString(),
            payload.GetProperty(SecurityClaimTypes.OurSubject).GetString());
    }

    private static ITokenService CreateTokenService(string issuer, string audience, string signingAlgorithm, string signingKey, string kid)
    {
        var jwt = new JwtOptions
        {
            Issuer = issuer,
            Audience = audience,
            SigningAlgorithm = signingAlgorithm,
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
