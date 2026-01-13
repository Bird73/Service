namespace Birdsoft.Security.Authentication.Tests.Unit;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authentication.Jwt;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

public sealed class InMemoryDenylistTests
{
    [Fact]
    public async Task ValidateAccessTokenAsync_WhenJtiIsDenylisted_Returns_RevokedToken()
    {
        var monitor = new FakeOptionsMonitor<JwtOptions>(new JwtOptions
        {
            Issuer = "https://security.test",
            Audience = "service",
            SigningKey = "dev-signing-key-123456789012345678901234567890",
            AccessTokenMinutes = 5,
            RefreshTokenDays = 7,
            ClockSkewSeconds = 0,
        });

        var env = new FakeOptionsMonitor<SecurityEnvironmentOptions>(new SecurityEnvironmentOptions { EnvironmentId = "test" });
        var safety = new FakeOptionsMonitor<SecuritySafetyOptions>(new SecuritySafetyOptions { Enabled = false, RequireEnvironmentId = false, EnforceTenantJwtIsolation = false });
        var hashing = new FakeOptionsMonitor<RefreshTokenHashingOptions>(new RefreshTokenHashingOptions { Pepper = "" });

        var hostEnvironment = new StubHostEnvironment { EnvironmentName = Environments.Development };
        var keys = new DefaultJwtKeyProvider(monitor);
        var sessions = new InMemorySessionStore();

        var tokens = new InMemoryTokenService(monitor, env, safety, hostEnvironment, hashing, keys, sessions);

        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var pair = await tokens.GenerateTokensAsync(tenantId, ourSubject);
        var ok = await tokens.ValidateAccessTokenAsync(pair.AccessToken);
        Assert.True(ok.Succeeded);
        Assert.NotNull(ok.Jti);

        await tokens.AddAsync(tenantId, ok.Jti!, DateTimeOffset.UtcNow.AddMinutes(10));

        var revoked = await tokens.ValidateAccessTokenAsync(pair.AccessToken);
        Assert.False(revoked.Succeeded);
        Assert.Equal("revoked_token", revoked.ErrorCode);
    }

    private sealed class FakeOptionsMonitor<T>(T current) : IOptionsMonitor<T>
    {
        public T CurrentValue => current;
        public T Get(string? name) => current;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
