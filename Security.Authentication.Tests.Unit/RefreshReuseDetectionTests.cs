namespace Birdsoft.Security.Authentication.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authentication.Jwt;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

public sealed class RefreshReuseDetectionTests
{
    [Fact]
    public async Task Refresh_Reusing_Old_RefreshToken_Terminates_Session_And_Returns_Reuse_ErrorCode()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var sessions = new InMemorySessionStore();
        var tokenService = CreateTokenService(sessions);

        var first = await tokenService.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        var sessionIdRaw = JwtTestHelpers.DecodeJwtPayload(first.AccessToken)
            .GetProperty(SecurityClaimTypes.SessionId)
            .GetString();
        Assert.False(string.IsNullOrWhiteSpace(sessionIdRaw));
        Assert.True(Guid.TryParse(sessionIdRaw, out var sessionId));

        // First refresh rotates the refresh token.
        var rotated = await tokenService.RefreshAsync(tenantId, first.RefreshToken);
        Assert.True(rotated.Succeeded);
        Assert.NotNull(rotated.Tokens);

        // Reuse the old refresh token should trigger reuse detection and terminate the session.
        var reused = await tokenService.RefreshAsync(tenantId, first.RefreshToken);
        Assert.False(reused.Succeeded);
        Assert.Equal(AuthErrorCodes.RefreshTokenReuseDetected, reused.ErrorCode);

        var active = await sessions.IsSessionActiveAsync(tenantId, sessionId);
        Assert.False(active);
    }

    private static ITokenService CreateTokenService(ISessionStore sessions)
    {
        var jwt = new JwtOptions
        {
            Issuer = "https://security.test",
            Audience = "service",
            SigningAlgorithm = "HS256",
            SigningKey = "unit-test-signing-key",
            Kid = "k1",
            AccessTokenMinutes = 5,
            RefreshTokenDays = 7,
            ClockSkewSeconds = 30,
        };

        IOptionsMonitor<JwtOptions> monitor = new FakeOptionsMonitor<JwtOptions>(jwt);
        IOptionsMonitor<SecurityEnvironmentOptions> env = new FakeOptionsMonitor<SecurityEnvironmentOptions>(new SecurityEnvironmentOptions { EnvironmentId = "test" });
        IOptionsMonitor<SecuritySafetyOptions> safety = new FakeOptionsMonitor<SecuritySafetyOptions>(new SecuritySafetyOptions { Enabled = false, RequireEnvironmentId = false, EnforceTenantJwtIsolation = false });
        IOptionsMonitor<RefreshTokenHashingOptions> hashing = new FakeOptionsMonitor<RefreshTokenHashingOptions>(new RefreshTokenHashingOptions());
        IHostEnvironment hostEnvironment = new FakeHostEnvironment { EnvironmentName = Environments.Development };
        IJwtKeyProvider keys = new DefaultJwtKeyProvider(monitor);

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
