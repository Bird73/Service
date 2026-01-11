namespace Birdsoft.Security.Authentication.Tests.Unit;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Text;
using System.Text.Json;

public sealed class GovernanceSessionInvalidationTests
{
    [Fact]
    public async Task ValidateAccessToken_Fails_When_Tenant_Suspended()
    {
        await using var env = await CreateEfEnvironmentAsync();
        using var scope = env.Services.CreateScope();

        var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var tenants = scope.ServiceProvider.GetRequiredService<ITenantRepository>();

        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var pair = await tokens.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        _ = await tenants.UpdateStatusAsync(tenantId, TenantStatus.Suspended);

        var validation = await tokens.ValidateAccessTokenAsync(pair.AccessToken);
        Assert.False(validation.Succeeded);
        Assert.Equal("tenant_suspended", validation.ErrorCode);
    }

    [Fact]
    public async Task ValidateAccessToken_Fails_When_User_Disabled()
    {
        await using var env = await CreateEfEnvironmentAsync();
        using var scope = env.Services.CreateScope();

        var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var subjects = scope.ServiceProvider.GetRequiredService<ISubjectRepository>();

        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var pair = await tokens.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        _ = await subjects.UpdateStatusAsync(tenantId, ourSubject, UserStatus.Disabled);

        var validation = await tokens.ValidateAccessTokenAsync(pair.AccessToken);
        Assert.False(validation.Succeeded);
        Assert.Equal("user_disabled", validation.ErrorCode);
    }

    [Fact]
    public async Task ValidateAccessToken_Fails_When_Session_Terminated()
    {
        await using var env = await CreateEfEnvironmentAsync();
        using var scope = env.Services.CreateScope();

        var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var sessions = scope.ServiceProvider.GetRequiredService<ISessionStore>();

        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var pair = await tokens.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        var sessionId = ReadGuidClaimFromJwt(pair.AccessToken, Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.SessionId);
        Assert.NotNull(sessionId);

        await sessions.TerminateSessionAsync(tenantId, sessionId!.Value, DateTimeOffset.UtcNow, reason: "test");

        var validation = await tokens.ValidateAccessTokenAsync(pair.AccessToken);
        Assert.False(validation.Succeeded);
        Assert.Equal("session_terminated", validation.ErrorCode);
    }

    [Fact]
    public async Task Refresh_Fails_When_Session_Terminated()
    {
        await using var env = await CreateEfEnvironmentAsync();
        using var scope = env.Services.CreateScope();

        var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var sessions = scope.ServiceProvider.GetRequiredService<ISessionStore>();

        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var pair = await tokens.GenerateTokensAsync(tenantId, ourSubject, roles: [], scopes: []);
        var sessionId = ReadGuidClaimFromJwt(pair.AccessToken, Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.SessionId);
        Assert.NotNull(sessionId);

        await sessions.TerminateSessionAsync(tenantId, sessionId!.Value, DateTimeOffset.UtcNow, reason: "test");

        var refreshed = await tokens.RefreshAsync(pair.RefreshToken);
        Assert.False(refreshed.Succeeded);
        Assert.Equal("session_terminated", refreshed.ErrorCode);
    }

    private static Guid? ReadGuidClaimFromJwt(string jwt, string claimType)
    {
        var parts = jwt.Split('.');
        Assert.True(parts.Length == 3);

        var json = Encoding.UTF8.GetString(DecodeBase64Url(parts[1]));
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (!root.TryGetProperty(claimType, out var prop))
        {
            return null;
        }

        var value = prop.GetString();
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return Guid.TryParse(value, out var guid) ? guid : null;
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

    private sealed class EfTestEnvironment : IAsyncDisposable
    {
        public required SqliteConnection Connection { get; init; }
        public required ServiceProvider Services { get; init; }

        public async ValueTask DisposeAsync()
        {
            await Connection.DisposeAsync();
            await Services.DisposeAsync();
        }
    }

    private static async Task<EfTestEnvironment> CreateEfEnvironmentAsync()
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

        var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();

        var services = new ServiceCollection();
        services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(conn));
        services.AddSecurityEfCoreDataAccess();

        IOptionsMonitor<JwtOptions> monitor = new FakeOptionsMonitor<JwtOptions>(jwt);
        services.AddSingleton(monitor);
        services.AddSingleton<Birdsoft.Security.Authentication.Jwt.IJwtKeyProvider>(sp => new Birdsoft.Security.Authentication.Jwt.DefaultJwtKeyProvider(sp.GetRequiredService<IOptionsMonitor<JwtOptions>>()));

        services.AddScoped<ITokenService, Birdsoft.Security.Authentication.Persistence.RepositoryTokenService>();

        var provider = services.BuildServiceProvider();

        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
            _ = await db.Database.EnsureCreatedAsync();
        }

        return new EfTestEnvironment { Connection = conn, Services = (ServiceProvider)provider };
    }

    private sealed class FakeOptionsMonitor<T>(T current) : IOptionsMonitor<T>
        where T : class
    {
        public T CurrentValue => current;
        public T Get(string? name) => current;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
