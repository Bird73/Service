namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Data.EfCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

public sealed class ProtectedEndpointAuthorizationContractTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static void TryDeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        for (var i = 0; i < 5; i++)
        {
            try
            {
                File.Delete(path);
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(50);
            }
            catch (UnauthorizedAccessException)
            {
                Thread.Sleep(50);
            }
        }
    }

    private static async Task WithTempDbAsync(Func<AuthenticationApiFactory, HttpClient, Task> run)
    {
        var dbPath = CreateTempSqliteDbPath();
        AuthenticationApiFactory? factory = null;
        HttpClient? client = null;

        try
        {
            factory = CreateEfFactory(dbPath);
            client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
            {
                // Avoid UseHttpsRedirection-triggered redirects that drop Authorization headers.
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });
            await run(factory, client);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    private static string CreateTempSqliteDbPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), "Birdsoft.Security.Authentication.Tests");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"security-{Guid.NewGuid():N}.db");
    }

    private static AuthenticationApiFactory CreateEfFactory(string dbPath)
    {
        var cs = $"Data Source={dbPath}";
        return new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            SecurityDbConnectionString = cs,
            EnableTestEndpoints = true,
        });
    }

    private static async Task EnsureDbCreatedAsync(AuthenticationApiFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetService<SecurityDbContext>();
        if (db is not null)
        {
            await db.Database.EnsureCreatedAsync();
        }
    }

    private static async Task<TokenPair> IssueTokensAsync(AuthenticationApiFactory factory, Guid tenantId, Guid ourSubject, IReadOnlyList<string>? roles = null, IReadOnlyList<string>? scopes = null)
    {
        await EnsureDbCreatedAsync(factory);
        using var scope = factory.Services.CreateScope();
        var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
        return await tokens.GenerateTokensAsync(tenantId, ourSubject, roles, scopes);
    }

    private static HttpRequestMessage CreateGet(string path, string? accessToken)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        return req;
    }

    [Fact]
    public async Task Protected_NoToken_Returns_401()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            _ = factory;
            using var req = CreateGet("/api/v1/test/protected", accessToken: null);
            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        });
    }

    [Fact]
    public async Task ProtectedScope_MissingScope_Returns_403_InsufficientScope()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var pair = await IssueTokensAsync(factory, tenantId, ourSubject, roles: null, scopes: ["scope:write"]);

            using var req = CreateGet("/api/v1/test/protected-scope", pair.AccessToken);
            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("insufficient_scope", body.Error!.Code);
        });
    }

    [Fact]
    public async Task ProtectedScope_WithScope_Returns_200()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var pair = await IssueTokensAsync(factory, tenantId, ourSubject, roles: null, scopes: ["scope:read"]);

            using var req = CreateGet("/api/v1/test/protected-scope", pair.AccessToken);
            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        });
    }

    [Fact]
    public async Task ProtectedRole_MissingRole_Returns_403_Forbidden()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var pair = await IssueTokensAsync(factory, tenantId, ourSubject, roles: ["User"], scopes: null);

            using var req = CreateGet("/api/v1/test/protected-role", pair.AccessToken);
            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("forbidden", body.Error!.Code);
        });
    }

    [Fact]
    public async Task ProtectedRole_WithRole_Returns_200()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var pair = await IssueTokensAsync(factory, tenantId, ourSubject, roles: ["Admin"], scopes: null);

            using var req = CreateGet("/api/v1/test/protected-role", pair.AccessToken);
            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        });
    }
}
