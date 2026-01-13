namespace Birdsoft.Security.Authentication.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authentication.Jwt;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

public sealed class JwtTimeBoundariesTests
{
    [Fact]
    public async Task ValidateAccessToken_Fails_When_Nbf_Not_Reached()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var clock = new ManualTimeProvider(DateTimeOffset.UnixEpoch.AddHours(1));
        var service = CreateTokenService(clock, clockSkewSeconds: 0);

        var pair = await service.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        clock.SetUtcNow(DateTimeOffset.UnixEpoch);

        var result = await service.ValidateAccessTokenAsync(pair.AccessToken);

        Assert.False(result.Succeeded);
        Assert.Equal(AuthErrorCodes.TokenNotYetValid, result.ErrorCode);
    }

    [Fact]
    public async Task ValidateAccessToken_Fails_When_Exp_Passed()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var clock = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var service = CreateTokenService(clock, clockSkewSeconds: 0);

        var pair = await service.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);

        var payload = JwtTestHelpers.DecodeJwtPayload(pair.AccessToken);
        var exp = payload.GetProperty("exp").GetInt64();
        clock.SetUtcNow(DateTimeOffset.FromUnixTimeSeconds(exp + 1));

        var result = await service.ValidateAccessTokenAsync(pair.AccessToken);

        Assert.False(result.Succeeded);
        Assert.Equal(AuthErrorCodes.TokenExpired, result.ErrorCode);
    }

    [Fact]
    public async Task ValidateAccessToken_Succeeds_When_Now_Equals_Exp_With_Zero_Skew()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var clock = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var service = CreateTokenService(clock, clockSkewSeconds: 0);

        var pair = await service.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);

        var payload = JwtTestHelpers.DecodeJwtPayload(pair.AccessToken);
        var exp = payload.GetProperty("exp").GetInt64();

        // Deterministic boundary rule:
        // - valid if now <= exp + skew
        // - expired only when now > exp + skew
        clock.SetUtcNow(DateTimeOffset.FromUnixTimeSeconds(exp));

        var ok = await service.ValidateAccessTokenAsync(pair.AccessToken);
        Assert.True(ok.Succeeded);

        clock.SetUtcNow(DateTimeOffset.FromUnixTimeSeconds(exp + 1));
        var expired = await service.ValidateAccessTokenAsync(pair.AccessToken);

        Assert.False(expired.Succeeded);
        Assert.Equal(AuthErrorCodes.TokenExpired, expired.ErrorCode);
    }

    [Fact]
    public async Task ValidateAccessToken_ClockSkew_Allows_Nbf_Within_Skew()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        // Issue token 20 seconds "in the future" relative to validation time.
        var clock = new ManualTimeProvider(DateTimeOffset.UnixEpoch.AddSeconds(20));
        var service = CreateTokenService(clock, clockSkewSeconds: 30);

        var pair = await service.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        clock.SetUtcNow(DateTimeOffset.UnixEpoch);

        var result = await service.ValidateAccessTokenAsync(pair.AccessToken);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAccessToken_ClockSkew_Allows_Exp_Within_Skew_But_Fails_Beyond()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var clock = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var service = CreateTokenService(clock, clockSkewSeconds: 30);

        var pair = await service.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        var payload = JwtTestHelpers.DecodeJwtPayload(pair.AccessToken);
        var exp = payload.GetProperty("exp").GetInt64();

        clock.SetUtcNow(DateTimeOffset.FromUnixTimeSeconds(exp + 20));
        var withinSkew = await service.ValidateAccessTokenAsync(pair.AccessToken);
        Assert.True(withinSkew.Succeeded);

        clock.SetUtcNow(DateTimeOffset.FromUnixTimeSeconds(exp + 31));
        var beyondSkew = await service.ValidateAccessTokenAsync(pair.AccessToken);
        Assert.False(beyondSkew.Succeeded);
        Assert.Equal(AuthErrorCodes.TokenExpired, beyondSkew.ErrorCode);
    }

    private static ITokenService CreateTokenService(ManualTimeProvider clock, int clockSkewSeconds)
    {
        var jwt = new JwtOptions
        {
            Issuer = "https://security.test",
            Audience = "service",
            SigningAlgorithm = "HS256",
            SigningKey = "unit-test-key",
            Kid = "k1",
            AccessTokenMinutes = 5,
            RefreshTokenDays = 7,
            ClockSkewSeconds = clockSkewSeconds,
        };

        IOptionsMonitor<JwtOptions> monitor = new FakeOptionsMonitor<JwtOptions>(jwt);
        IOptionsMonitor<SecurityEnvironmentOptions> env = new FakeOptionsMonitor<SecurityEnvironmentOptions>(new SecurityEnvironmentOptions { EnvironmentId = "test" });
        IOptionsMonitor<SecuritySafetyOptions> safety = new FakeOptionsMonitor<SecuritySafetyOptions>(new SecuritySafetyOptions { Enabled = false, RequireEnvironmentId = false, EnforceTenantJwtIsolation = false });
        IOptionsMonitor<RefreshTokenHashingOptions> hashing = new FakeOptionsMonitor<RefreshTokenHashingOptions>(new RefreshTokenHashingOptions());
        IHostEnvironment hostEnvironment = new FakeHostEnvironment { EnvironmentName = Environments.Development };
        IJwtKeyProvider keys = new DefaultJwtKeyProvider(monitor);
        ISessionStore sessions = new InMemorySessionStore();

        return new InMemoryTokenService(monitor, env, safety, hostEnvironment, hashing, keys, sessions, clock);
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

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void SetUtcNow(DateTimeOffset utcNow) => _utcNow = utcNow;
    }
}
