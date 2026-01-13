namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Data.EfCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

public sealed class CrossTenantHardeningContractTests
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
            client = factory.CreateClient();
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

    private static async Task<TokenPair> IssueTokensAsync(AuthenticationApiFactory factory, Guid tenantId, Guid ourSubject)
    {
        await EnsureDbCreatedAsync(factory);
        using var scope = factory.Services.CreateScope();
        var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
        return await tokens.GenerateTokensAsync(tenantId, ourSubject);
    }

    private static Task<HttpResponseMessage> PostRefreshAsync(HttpClient client, Guid tenantId, string refreshToken)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/token/refresh")
        {
            Content = JsonContent.Create(new RefreshRequest(refreshToken)),
        };
        req.Headers.Add("X-Tenant-Id", tenantId.ToString());
        return client.SendAsync(req);
    }

    private static HttpRequestMessage CreateRevokeRequest(Guid tenantId, string accessToken, TokenRevokeRequest body)
    {
        var msg = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/token/revoke")
        {
            Content = JsonContent.Create(body),
        };

        msg.Headers.Add("X-Tenant-Id", tenantId.ToString());
        msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return msg;
    }

    private static Task<HttpResponseMessage> GetCallbackAsync(HttpClient client, Guid tenantId, string provider, string code, string state)
    {
        var url = $"/api/v1/auth/oidc/{Uri.EscapeDataString(provider)}/callback?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state)}";
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Add("X-Tenant-Id", tenantId.ToString());
        return client.SendAsync(req);
    }

    [Fact]
    public async Task CrossTenant_Refresh_HeaderTenantB_WithRefreshTokenFromTenantA_Returns_401_InvalidTenant()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantA = Guid.NewGuid();
            var tenantB = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();

            var tokensA = await IssueTokensAsync(factory, tenantA, ourSubject);

            var res = await PostRefreshAsync(client, tenantB, tokensA.RefreshToken);
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_tenant", body.Error!.Code);
        });
    }

    [Fact]
    public async Task CrossTenant_Revoke_BearerTenantB_WithRefreshTokenFromTenantA_Returns_403_Forbidden()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantA = Guid.NewGuid();
            var tenantB = Guid.NewGuid();
            var subjectA = Guid.NewGuid();
            var subjectB = Guid.NewGuid();

            var tokensA = await IssueTokensAsync(factory, tenantA, subjectA);
            var tokensB = await IssueTokensAsync(factory, tenantB, subjectB);

            using var req = CreateRevokeRequest(
                tenantB,
                tokensB.AccessToken,
                new TokenRevokeRequest(RefreshToken: tokensA.RefreshToken, AllDevices: false));

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("forbidden", body.Error!.Code);
        });
    }

    [Fact]
    public async Task OidcCallback_CrossTenant_HeaderTenantB_WithStateFromTenantA_Returns_400_InvalidState()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantA = Guid.NewGuid();
            var tenantB = Guid.NewGuid();

            string state;
            await EnsureDbCreatedAsync(factory);
            using (var scope = factory.Services.CreateScope())
            {
                var authState = scope.ServiceProvider.GetRequiredService<IAuthStateService>();
                var stateInfo = await authState.CreateStateAsync(tenantA);
                await authState.TryAttachOidcContextAsync(stateInfo.State, provider: "stub", codeVerifier: "cv", nonce: "nonce");
                state = stateInfo.State;
            }

            var res = await GetCallbackAsync(client, tenantB, provider: "stub", code: "external-sub-ct", state);
            Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_state", body.Error!.Code);
        });
    }

    [Fact]
    public async Task TenantResolution_Uses_TenantId_Claim_When_Header_Missing()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var pair = await IssueTokensAsync(factory, tenantId, ourSubject);

            // No X-Tenant-Id header: tenant should be resolved from the tenant_id claim in the JWT.
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/token/revoke")
            {
                Content = JsonContent.Create(new TokenRevokeRequest(RefreshToken: pair.RefreshToken, AllDevices: false)),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pair.AccessToken);

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.True(body!.Success);
        });
    }
}
