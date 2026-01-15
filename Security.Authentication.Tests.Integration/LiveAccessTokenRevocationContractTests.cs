namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

public sealed class LiveAccessTokenRevocationContractTests
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
            client = factory.CreateClient(new WebApplicationFactoryClientOptions
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
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    private static async Task<JwtBearerTokenPair> IssueAccessTokenAsync(AuthenticationApiFactory factory, Guid tenantId, Guid ourSubject)
    {
        await EnsureDbCreatedAsync(factory);
        using var scope = factory.Services.CreateScope();
        var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var pair = await tokens.GenerateTokensAsync(tenantId, ourSubject);
        return new JwtBearerTokenPair(AccessToken: pair.AccessToken);
    }

    private sealed record JwtBearerTokenPair(string AccessToken);

    [Fact]
    public async Task ProtectedEndpoint_After_User_Disabled_Returns_401_InvalidToken()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();

            var issued = await IssueAccessTokenAsync(factory, tenantId, ourSubject);

            using (var okReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/test/protected"))
            {
                okReq.Headers.Add("X-Tenant-Id", tenantId.ToString());
                okReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", issued.AccessToken);

                var okRes = await client.SendAsync(okReq);
                Assert.Equal(HttpStatusCode.OK, okRes.StatusCode);
            }

            using (var scope = factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
                var subject = await db.Subjects.FirstAsync(s => s.TenantId == tenantId && s.OurSubject == ourSubject);
                subject.Status = (int)UserStatus.Disabled;
                await db.SaveChangesAsync();
            }

            using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/test/protected");
            req.Headers.Add("X-Tenant-Id", tenantId.ToString());
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", issued.AccessToken);

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_token", body.Error!.Code);
        });
    }
}
