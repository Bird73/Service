namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Data.EfCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

public sealed class TokenRevokeContractTests
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

    private static HttpRequestMessage CreateRevokeRequest(Guid tenantId, string? accessToken, TokenRevokeRequest body)
    {
        var msg = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/token/revoke")
        {
            Content = JsonContent.Create(body),
        };

        // Tenant header keeps tenant middleware happy even in missing-bearer scenario.
        msg.Headers.Add("X-Tenant-Id", tenantId.ToString());

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        return msg;
    }

    [Fact]
    public async Task Missing_Bearer_Returns_401_MissingBearerToken()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            _ = factory;
            var tenantId = Guid.NewGuid();

            using var req = CreateRevokeRequest(tenantId, accessToken: null, new TokenRevokeRequest(RefreshToken: "any", AllDevices: false));
            var res = await client.SendAsync(req);

            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("missing_bearer_token", body.Error!.Code);
        });
    }

    [Fact]
    public async Task Revoke_SingleToken_Returns_200_And_Denylist_Blocks_AccessToken_Jti()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var pair = await IssueTokensAsync(factory, tenantId, ourSubject);

            using var revokeReq = CreateRevokeRequest(tenantId, pair.AccessToken, new TokenRevokeRequest(RefreshToken: pair.RefreshToken, AllDevices: false));
            var revokeRes = await client.SendAsync(revokeReq);
            Assert.Equal(HttpStatusCode.OK, revokeRes.StatusCode);

            // Validate via token service: should now fail due to denylist.
            using var scope = factory.Services.CreateScope();
            var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
            var validation = await tokens.ValidateAccessTokenAsync(pair.AccessToken);
            Assert.False(validation.Succeeded);
            Assert.Equal("revoked_token", validation.ErrorCode);

            // Also assert denylist contains the access token jti.
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(pair.AccessToken);
            var jti = jwt.Claims.First(c => string.Equals(c.Type, SecurityClaimTypes.Jti, StringComparison.Ordinal)).Value;
            var denylist = scope.ServiceProvider.GetRequiredService<IAccessTokenDenylistStore>();
            var exists = await denylist.ContainsAsync(tenantId, jti);
            Assert.True(exists);
        });
    }

    [Fact]
    public async Task Revoke_RefreshToken_NotOwnedBy_Subject_Returns_403_Forbidden()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var subjectA = Guid.NewGuid();
            var subjectB = Guid.NewGuid();

            var tokensA = await IssueTokensAsync(factory, tenantId, subjectA);
            var tokensB = await IssueTokensAsync(factory, tenantId, subjectB);

            using var revokeReq = CreateRevokeRequest(tenantId, tokensA.AccessToken, new TokenRevokeRequest(RefreshToken: tokensB.RefreshToken, AllDevices: false));
            var res = await client.SendAsync(revokeReq);

            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("forbidden", body.Error!.Code);
        });
    }
}
