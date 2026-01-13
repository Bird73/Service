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

public sealed class TokenRefreshContractTests
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
        // Note: Program.cs uses the presence of ConnectionStrings:SecurityDb to decide EF-backed services.
        var cs = $"Data Source={dbPath}";
        return new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            SecurityDbConnectionString = cs,
        });
    }

    private static async Task<TokenPair> IssueInitialTokensAsync(AuthenticationApiFactory factory, Guid tenantId, Guid ourSubject)
    {
        using var scope = factory.Services.CreateScope();

        var db = scope.ServiceProvider.GetService<SecurityDbContext>();
        if (db is not null)
        {
            await db.Database.EnsureCreatedAsync();
        }

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

    [Fact]
    public async Task Missing_RefreshToken_Returns_400_InvalidRequest()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();

            // Empty string triggers handler validation; tenant header required by middleware.
            var res = await PostRefreshAsync(client, tenantId, refreshToken: "");
            Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_request", body.Error!.Code);
        });
    }

    [Fact]
    public async Task Refresh_Rotates_RefreshToken_And_Allows_Using_New_Token()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var initial = await IssueInitialTokensAsync(factory, tenantId, ourSubject);

            var res1 = await PostRefreshAsync(client, tenantId, initial.RefreshToken);
            Assert.Equal(HttpStatusCode.OK, res1.StatusCode);

            var body1 = await res1.Content.ReadFromJsonAsync<ApiResponse<TokenPair>>(JsonOptions);
            Assert.NotNull(body1);
            Assert.True(body1!.Success);
            Assert.NotNull(body1.Data);
            Assert.False(string.IsNullOrWhiteSpace(body1.Data!.RefreshToken));
            Assert.NotEqual(initial.RefreshToken, body1.Data.RefreshToken);

            var res2 = await PostRefreshAsync(client, tenantId, body1.Data.RefreshToken);
            Assert.Equal(HttpStatusCode.OK, res2.StatusCode);

            var body2 = await res2.Content.ReadFromJsonAsync<ApiResponse<TokenPair>>(JsonOptions);
            Assert.NotNull(body2);
            Assert.True(body2!.Success);
            Assert.NotNull(body2.Data);
            Assert.False(string.IsNullOrWhiteSpace(body2.Data!.RefreshToken));
            Assert.NotEqual(body1.Data.RefreshToken, body2.Data.RefreshToken);
        });
    }

    [Fact]
    public async Task Refresh_Reusing_Replaced_Token_Returns_ReuseDetected_And_Terminates_Session()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var initial = await IssueInitialTokensAsync(factory, tenantId, ourSubject);

            var res1 = await PostRefreshAsync(client, tenantId, initial.RefreshToken);
            Assert.Equal(HttpStatusCode.OK, res1.StatusCode);

            var ok = await res1.Content.ReadFromJsonAsync<ApiResponse<TokenPair>>(JsonOptions);
            Assert.NotNull(ok);
            Assert.True(ok!.Success);
            var refreshed = ok.Data!;

            // Using the old refresh token again is treated as reuse (rotation replay) and should terminate the session.
            var resReuse = await PostRefreshAsync(client, tenantId, initial.RefreshToken);
            Assert.Equal(HttpStatusCode.Unauthorized, resReuse.StatusCode);

            var fail = await resReuse.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(fail);
            Assert.False(fail!.Success);
            Assert.Equal(Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.RefreshTokenReuseDetected, fail.Error!.Code);

            // Session should now be terminated: validating the access token (via /token/revoke) should yield session_terminated.
            var revokeReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/token/revoke")
            {
                Content = JsonContent.Create(new TokenRevokeRequest(RefreshToken: null, AllDevices: false)),
            };
            revokeReq.Headers.Add("X-Tenant-Id", tenantId.ToString());
            revokeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", refreshed.AccessToken);

            var resRevoke = await client.SendAsync(revokeReq);
            Assert.Equal(HttpStatusCode.Unauthorized, resRevoke.StatusCode);

            var revokeBody = await resRevoke.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(revokeBody);
            Assert.False(revokeBody!.Success);
            Assert.Equal("session_terminated", revokeBody.Error!.Code);
        });
    }

    [Fact]
    public async Task Refresh_After_TokenRevoked_Returns_401_RevokedRefreshToken()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var initial = await IssueInitialTokensAsync(factory, tenantId, ourSubject);

            // Revoke using the access token.
            var revokeReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/token/revoke")
            {
                Content = JsonContent.Create(new TokenRevokeRequest(RefreshToken: initial.RefreshToken, AllDevices: false)),
            };
            revokeReq.Headers.Add("X-Tenant-Id", tenantId.ToString());
            revokeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", initial.AccessToken);

            var revokeRes = await client.SendAsync(revokeReq);
            Assert.Equal(HttpStatusCode.OK, revokeRes.StatusCode);

            var refreshRes = await PostRefreshAsync(client, tenantId, initial.RefreshToken);
            Assert.Equal(HttpStatusCode.Unauthorized, refreshRes.StatusCode);

            var body = await refreshRes.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("revoked_refresh_token", body.Error!.Code);
        });
    }

    [Fact]
    public async Task Refresh_When_Tenant_Missing_Returns_401_InvalidTenant()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var initial = await IssueInitialTokensAsync(factory, tenantId, ourSubject);

            // Delete tenant row so refresh record exists but tenant lookup fails.
            using (var scope = factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
                await db.Database.EnsureCreatedAsync();
                var tenant = await db.Tenants.FirstAsync(t => t.TenantId == tenantId);
                db.Tenants.Remove(tenant);
                await db.SaveChangesAsync();
            }

            var refreshRes = await PostRefreshAsync(client, tenantId, initial.RefreshToken);
            Assert.Equal(HttpStatusCode.Unauthorized, refreshRes.StatusCode);

            var body = await refreshRes.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_tenant", body.Error!.Code);
        });
    }

    [Fact]
    public async Task Refresh_When_TokenVersion_Bumped_Returns_401_InvalidTokenVersion()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var initial = await IssueInitialTokensAsync(factory, tenantId, ourSubject);

            // Bump tenant token version after refresh token was issued.
            using (var scope = factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
                await db.Database.EnsureCreatedAsync();
                var tenant = await db.Tenants.FirstAsync(t => t.TenantId == tenantId);
                tenant.TokenVersion += 1;
                await db.SaveChangesAsync();
            }

            var refreshRes = await PostRefreshAsync(client, tenantId, initial.RefreshToken);
            Assert.Equal(HttpStatusCode.Unauthorized, refreshRes.StatusCode);

            var body = await refreshRes.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_token_version", body.Error!.Code);
        });
    }

    [Fact]
    public async Task Refresh_Concurrent_Rotation_With_Same_Token_Is_OneSuccess_OneFailure_And_Rotation_Is_Enforced()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            var initial = await IssueInitialTokensAsync(factory, tenantId, ourSubject);

            // Fire two refresh requests concurrently using the same refresh token.
            var t1 = PostRefreshAsync(client, tenantId, initial.RefreshToken);
            var t2 = PostRefreshAsync(client, tenantId, initial.RefreshToken);
            var res = await Task.WhenAll(t1, t2);

            Assert.Equal(2, res.Length);
            Assert.Equal(1, res.Count(r => r.StatusCode == HttpStatusCode.OK));
            Assert.Equal(1, res.Count(r => r.StatusCode == HttpStatusCode.Unauthorized));

            var okRes = res.Single(r => r.StatusCode == HttpStatusCode.OK);
            var failRes = res.Single(r => r.StatusCode == HttpStatusCode.Unauthorized);

            var okBody = await okRes.Content.ReadFromJsonAsync<ApiResponse<TokenPair>>(JsonOptions);
            Assert.NotNull(okBody);
            Assert.True(okBody!.Success);
            Assert.NotNull(okBody.Data);
            Assert.False(string.IsNullOrWhiteSpace(okBody.Data!.RefreshToken));
            Assert.NotEqual(initial.RefreshToken, okBody.Data.RefreshToken);

            var failBody = await failRes.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(failBody);
            Assert.False(failBody!.Success);
            Assert.True(
                string.Equals(failBody.Error!.Code, "revoked_refresh_token", StringComparison.Ordinal)
                || string.Equals(failBody.Error.Code, Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.RefreshTokenReuseDetected, StringComparison.Ordinal));

            // Session behavior depends on whether the loser observed a rotated token (reuse detection) or lost the rotate transaction.
            var revokeReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/token/revoke")
            {
                Content = JsonContent.Create(new TokenRevokeRequest(RefreshToken: null, AllDevices: false)),
            };
            revokeReq.Headers.Add("X-Tenant-Id", tenantId.ToString());

            if (string.Equals(failBody.Error.Code, "revoked_refresh_token", StringComparison.Ordinal))
            {
                // Rotation must be effective: using the new refresh token should succeed.
                var res2 = await PostRefreshAsync(client, tenantId, okBody.Data.RefreshToken);
                Assert.Equal(HttpStatusCode.OK, res2.StatusCode);

                var okBody2 = await res2.Content.ReadFromJsonAsync<ApiResponse<TokenPair>>(JsonOptions);
                Assert.NotNull(okBody2);
                Assert.True(okBody2!.Success);
                Assert.NotNull(okBody2.Data);

                // Session should remain active.
                revokeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", okBody2.Data.AccessToken);
                var revokeRes = await client.SendAsync(revokeReq);
                Assert.Equal(HttpStatusCode.OK, revokeRes.StatusCode);
            }
            else
            {
                // If the loser observed a rotated token, it's treated as reuse attack and session may be terminated.
                // Attempting to use the newly issued refresh token may fail due to session termination.
                var res2 = await PostRefreshAsync(client, tenantId, okBody.Data.RefreshToken);
                Assert.Equal(HttpStatusCode.Unauthorized, res2.StatusCode);

                var body2 = await res2.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
                Assert.NotNull(body2);
                Assert.False(body2!.Success);
                Assert.True(
                    string.Equals(body2.Error!.Code, "session_terminated", StringComparison.Ordinal)
                    || string.Equals(body2.Error.Code, "revoked_refresh_token", StringComparison.Ordinal)
                    || string.Equals(body2.Error.Code, Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.RefreshTokenReuseDetected, StringComparison.Ordinal));

                revokeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", okBody.Data.AccessToken);
                var revokeRes = await client.SendAsync(revokeReq);
                Assert.Equal(HttpStatusCode.Unauthorized, revokeRes.StatusCode);
                var revokeBody = await revokeRes.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
                Assert.NotNull(revokeBody);
                Assert.False(revokeBody!.Success);
                Assert.Equal("session_terminated", revokeBody.Error!.Code);
            }

            // Further use of the old refresh token must fail (rotation enforcement).
            var resOld = await PostRefreshAsync(client, tenantId, initial.RefreshToken);
            Assert.Equal(HttpStatusCode.Unauthorized, resOld.StatusCode);
        });
    }
}
