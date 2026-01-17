extern alias Authn;
extern alias Authz;

namespace Birdsoft.Security.Bootstrap.Tests.Integration;

using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Infrastructure.Logging.Abstractions;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Xunit.Sdk;

public sealed class DefaultAdminBootstrapIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static readonly Guid DefaultAdminSubject = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    private sealed class UnhandledExceptionCapture
    {
        private readonly object _gate = new();
        public Exception? LastException { get; private set; }
        public string? LastMessageTemplate { get; private set; }

        public void Capture(Exception? exception, string messageTemplate)
        {
            lock (_gate)
            {
                LastException = exception;
                LastMessageTemplate = messageTemplate;
            }
        }
    }

    [Fact]
    public async Task PlatformToken_Expired_Is_401()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);
            var authzClient = authzFactory.CreateClient();

            var expired = CreateExpiredPlatformJwt(issuer, audience, signingKey);
            authzClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", expired);

            var res = await authzClient.GetAsync("/api/v1/platform/products");
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task PlatformToken_Revoke_Immediately_Invalidates_Previously_Issued_Token()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);

            var authnClient = authnFactory.CreateClient();
            var authzClient = authzFactory.CreateClient();

            // Mint platform token.
            var platformRes = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "revoke-test" },
                JsonOptions);
            if (platformRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await platformRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/platform/auth/bootstrap/exchange failed: {(int)platformRes.StatusCode} {platformRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var platformBody = await platformRes.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            Assert.NotNull(platformBody);
            Assert.True(platformBody!.Success);
            var token = platformBody.Data!.PlatformAccessToken;

            // Sanity: token can call platform API.
            authzClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var okRes = await authzClient.GetAsync("/api/v1/platform/products");
            Assert.Equal(HttpStatusCode.OK, okRes.StatusCode);

            // Revoke.
            var revokeRes = await authzClient.PostAsync("/api/v1/platform/tokens/revoke?reason=revoke-test", content: null);
            Assert.Equal(HttpStatusCode.NoContent, revokeRes.StatusCode);

            // Old token must fail immediately.
            var denied = await authzClient.GetAsync("/api/v1/platform/products");
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);

            // New token should work.
            var platformRes2 = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "revoke-test-2" },
                JsonOptions);
            Assert.Equal(HttpStatusCode.OK, platformRes2.StatusCode);

            var platformBody2 = await platformRes2.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            Assert.True(platformBody2!.Success);
            authzClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", platformBody2.Data!.PlatformAccessToken);

            var okRes2 = await authzClient.GetAsync("/api/v1/platform/products");
            Assert.Equal(HttpStatusCode.OK, okRes2.StatusCode);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task TenantToken_Cannot_Call_Platform_Api_Is_403()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);

            var authnClient = authnFactory.CreateClient();
            var authzClient = authzFactory.CreateClient();

            // Initialize DB.
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "t1",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");
            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            Assert.Equal(HttpStatusCode.OK, bootstrapRes.StatusCode);
            var bootstrapBody = await bootstrapRes.Content.ReadFromJsonAsync<ApiResponse<BootstrapResult>>(JsonOptions);
            Assert.True(bootstrapBody!.Success);

            using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "admin", Password: "Passw0rd!"), options: JsonOptions),
            };
            loginReq.Headers.Add("X-Tenant-Id", bootstrapBody.Data!.TenantId.ToString());

            var loginRes = await authnClient.SendAsync(loginReq);
            Assert.Equal(HttpStatusCode.OK, loginRes.StatusCode);

            var loginBody = await loginRes.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(loginBody);
            Assert.True(loginBody!.Success);
            Assert.NotNull(loginBody.Data);
            Assert.NotNull(loginBody.Data!.Tokens);

            var accessToken = loginBody.Data!.Tokens!.AccessToken;
            Assert.False(string.IsNullOrWhiteSpace(accessToken));

            authzClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var res = await authzClient.GetAsync("/api/v1/platform/products");
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task Platform_AuditLogs_Can_Query_After_Write()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);

            var authnClient = authnFactory.CreateClient();
            var authzClient = authzFactory.CreateClient();

            var platformRes = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "audit-test" },
                JsonOptions);
            if (platformRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await platformRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/platform/auth/bootstrap/exchange failed: {(int)platformRes.StatusCode} {platformRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var platformBody = await platformRes.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            var token = platformBody!.Data!.PlatformAccessToken;
            authzClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // Write an audit event.
            var productKey = "auditp" + Guid.NewGuid().ToString("N")[..8];
            var create = await authzClient.PostAsJsonAsync(
                "/api/v1/platform/products",
                new { productKey, displayName = "Audit Product", description = "x", status = (int)ProductStatus.Enabled, reason = "audit" },
                JsonOptions);
            Assert.Equal(HttpStatusCode.Created, create.StatusCode);

            var logs = await authzClient.GetAsync("/api/v1/platform/audit-logs?action=platform.product.create&take=50");
            if (logs.StatusCode != HttpStatusCode.OK)
            {
                var debug = await logs.Content.ReadAsStringAsync();
                var capture = authzFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/platform/audit-logs failed: {(int)logs.StatusCode} {logs.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var json = await logs.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            Assert.True(doc.RootElement.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.True);
            Assert.True(doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array);
            Assert.Contains(data.EnumerateArray(), e => e.TryGetProperty("code", out var c) && c.GetString() == "platform.product.create");
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task Platform_Crud_Duplicate_Product_And_Permission_Return_409()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);

            var authnClient = authnFactory.CreateClient();
            var authzClient = authzFactory.CreateClient();

            var platformRes = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "conflict-test" },
                JsonOptions);
            if (platformRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await platformRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/platform/auth/bootstrap/exchange failed: {(int)platformRes.StatusCode} {platformRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var platformBody = await platformRes.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            authzClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", platformBody!.Data!.PlatformAccessToken);

            var productKey = "confp" + Guid.NewGuid().ToString("N")[..8];
            var create1 = await authzClient.PostAsJsonAsync(
                "/api/v1/platform/products",
                new { productKey, displayName = "P", description = "x", status = (int)ProductStatus.Enabled, reason = "c1" },
                JsonOptions);
            Assert.Equal(HttpStatusCode.Created, create1.StatusCode);

            var create2 = await authzClient.PostAsJsonAsync(
                "/api/v1/platform/products",
                new { productKey, displayName = "P2", description = "x", status = (int)ProductStatus.Enabled, reason = "c2" },
                JsonOptions);
            Assert.Equal(HttpStatusCode.Conflict, create2.StatusCode);

            var permKey = "perm:" + Guid.NewGuid().ToString("N")[..8];
            var p1 = await authzClient.PostAsJsonAsync(
                "/api/v1/platform/permissions",
                new { permissionKey = permKey, productKey, description = "d", reason = "p1" },
                JsonOptions);
            Assert.Equal(HttpStatusCode.Created, p1.StatusCode);

            var p2 = await authzClient.PostAsJsonAsync(
                "/api/v1/platform/permissions",
                new { permissionKey = permKey, productKey, description = "d", reason = "p2" },
                JsonOptions);
            Assert.Equal(HttpStatusCode.Conflict, p2.StatusCode);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task Product_Disable_Denies_Refresh_Exchange()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);

            var authnClient = authnFactory.CreateClient();
            var authzClient = authzFactory.CreateClient();

            // Initialize DB with a tenant + a product-bound permission (security.manage -> product security).
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "t1",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");
            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            if (bootstrapRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await bootstrapRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/bootstrap failed: {(int)bootstrapRes.StatusCode} {bootstrapRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var bootstrapBody = await bootstrapRes.Content.ReadFromJsonAsync<ApiResponse<BootstrapResult>>(JsonOptions);
            Assert.NotNull(bootstrapBody);
            Assert.True(bootstrapBody!.Success);
            var tenantId = bootstrapBody.Data!.TenantId;
            var ourSubject = bootstrapBody.Data!.OurSubject;

            // Login to get a refresh token.
            using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "admin", Password: "Passw0rd!"), options: JsonOptions),
            };
            loginReq.Headers.Add("X-Tenant-Id", tenantId.ToString());
            var loginRes = await authnClient.SendAsync(loginReq);
            if (loginRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await loginRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/auth/password/login failed: {(int)loginRes.StatusCode} {loginRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var loginBody = await loginRes.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(loginBody);
            Assert.True(loginBody!.Success);
            var tenantAccessToken = loginBody.Data!.Tokens!.AccessToken;
            var refreshToken = loginBody.Data!.Tokens!.RefreshToken;
            Assert.False(string.IsNullOrWhiteSpace(refreshToken));

            // Ensure the subject has a product-bound permission so refresh validation is exercised.
            using var grantReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenant/users/{ourSubject}/permissions")
            {
                Content = JsonContent.Create(new TenantSetUserPermissionRequest(PermissionKey: "security.manage", Reason: "refresh-deny-test"), options: JsonOptions),
            };
            grantReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tenantAccessToken);
            var grantRes = await authzClient.SendAsync(grantReq);
            Assert.Equal(HttpStatusCode.OK, grantRes.StatusCode);

            // Permission grant bumps subject token version; re-login to get a refresh token bound to the new version.
            using var loginReq2 = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "admin", Password: "Passw0rd!"), options: JsonOptions),
            };
            loginReq2.Headers.Add("X-Tenant-Id", tenantId.ToString());
            var loginRes2 = await authnClient.SendAsync(loginReq2);
            Assert.Equal(HttpStatusCode.OK, loginRes2.StatusCode);

            var loginBody2 = await loginRes2.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(loginBody2);
            Assert.True(loginBody2!.Success);
            refreshToken = loginBody2.Data!.Tokens!.RefreshToken;
            Assert.False(string.IsNullOrWhiteSpace(refreshToken));

            // Disable the product via platform API.
            var platformRes = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "refresh-governance" },
                JsonOptions);
            if (platformRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await platformRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/platform/auth/bootstrap/exchange failed: {(int)platformRes.StatusCode} {platformRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var platformBody = await platformRes.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            using var disableReq = new HttpRequestMessage(HttpMethod.Put, "/api/v1/platform/products/security")
            {
                Content = JsonContent.Create(new { status = (int)ProductStatus.Disabled, reason = "refresh-deny-test" }, options: JsonOptions),
            };
            disableReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", platformBody!.Data!.PlatformAccessToken);
            var disableRes = await authzClient.SendAsync(disableReq);
            Assert.Equal(HttpStatusCode.OK, disableRes.StatusCode);

            // Refresh should be denied immediately.
            using var refreshReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/token/refresh")
            {
                Content = JsonContent.Create(new { refreshToken }, options: JsonOptions),
            };
            refreshReq.Headers.Add("X-Tenant-Id", tenantId.ToString());

            var refreshRes = await authnClient.SendAsync(refreshReq);
            Assert.Equal(HttpStatusCode.Unauthorized, refreshRes.StatusCode);

            var json = await refreshRes.Content.ReadAsStringAsync();
            string? errorCode = null;
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.Object)
                {
                    if (err.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String)
                    {
                        errorCode = code.GetString();
                    }
                }
                else if (doc.RootElement.TryGetProperty("code", out var rootCode) && rootCode.ValueKind == JsonValueKind.String)
                {
                    errorCode = rootCode.GetString();
                }
            }
            catch
            {
                // Ignore parse errors and fall back to substring match.
            }

            if (errorCode is not null)
            {
                Assert.Equal(AuthErrorCodes.ProductNotEnabled, errorCode);
            }
            else
            {
                Assert.True(json.Contains(AuthErrorCodes.ProductNotEnabled, StringComparison.OrdinalIgnoreCase), json);
            }
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task DbBootstrapKeys_Override_ConfigBootstrapKey_And_Revocation_Is_Immediate()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);

            var authnClient = authnFactory.CreateClient();
            var authzClient = authzFactory.CreateClient();

            // Initialize DB (uses legacy config bootstrap key because DB has no bootstrap keys yet).
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "t1",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");
            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            if (bootstrapRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await bootstrapRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/bootstrap failed: {(int)bootstrapRes.StatusCode} {bootstrapRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            // Get an initial platform token via legacy bootstrap key.
            var exchangeRes1 = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), role = "platform.super_admin", reason = "bootstrap-key-db-test" },
                JsonOptions);
            if (exchangeRes1.StatusCode != HttpStatusCode.OK)
            {
                var debug = await exchangeRes1.Content.ReadAsStringAsync();
                Assert.Fail($"initial /platform/auth/bootstrap/exchange failed: {(int)exchangeRes1.StatusCode} {exchangeRes1.StatusCode}\n{debug}");
            }
            var exchangeBody1 = await exchangeRes1.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            Assert.NotNull(exchangeBody1);
            Assert.True(exchangeBody1!.Success);
            var platformAccessToken = exchangeBody1.Data!.PlatformAccessToken;

            // Create a DB-backed bootstrap key via platform API.
            using var createKeyReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/bootstrap-keys")
            {
                Content = JsonContent.Create(new { label = "test", expiresAt = (string?)null }, options: JsonOptions),
            };
            createKeyReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", platformAccessToken);
            var createKeyRes = await authzClient.SendAsync(createKeyReq);
            if (createKeyRes.StatusCode != HttpStatusCode.Created)
            {
                var debug = await createKeyRes.Content.ReadAsStringAsync();
                Assert.Fail($"/platform/bootstrap-keys create failed: {(int)createKeyRes.StatusCode} {createKeyRes.StatusCode}\n{debug}");
            }

            var createKeyBody = await createKeyRes.Content.ReadFromJsonAsync<ApiResponse<JsonElement>>(JsonOptions);
            Assert.NotNull(createKeyBody);
            Assert.True(createKeyBody!.Success);
            Assert.True(createKeyBody.Data!.ValueKind == JsonValueKind.Object);
            Assert.True(createKeyBody.Data!.TryGetProperty("plaintext_key", out var plaintextEl));
            var dbBootstrapKey = plaintextEl.GetString();
            Assert.False(string.IsNullOrWhiteSpace(dbBootstrapKey));

            Assert.True(createKeyBody.Data!.TryGetProperty("record", out var recordEl));
            Assert.True(recordEl.TryGetProperty("id", out var idEl));
            var keyId = idEl.GetGuid();
            Assert.NotEqual(Guid.Empty, keyId);

            // After a DB key exists, legacy config bootstrap keys must be rejected (401).
            var exchangeRes2 = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "should-fail" },
                JsonOptions);
            Assert.Equal(HttpStatusCode.Unauthorized, exchangeRes2.StatusCode);

            // DB key must work.
            var exchangeRes3 = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = dbBootstrapKey, ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "should-succeed" },
                JsonOptions);
            Assert.Equal(HttpStatusCode.OK, exchangeRes3.StatusCode);

            // Revoke the DB key and verify immediate 401.
            using var revokeReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/platform/bootstrap-keys/{keyId}/revoke")
            {
                Content = JsonContent.Create(new { reason = "test-revoke" }, options: JsonOptions),
            };
            revokeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", platformAccessToken);
            var revokeRes = await authzClient.SendAsync(revokeReq);
            Assert.Equal(HttpStatusCode.OK, revokeRes.StatusCode);

            var exchangeRes4 = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = dbBootstrapKey, ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "revoked-should-fail" },
                JsonOptions);
            Assert.Equal(HttpStatusCode.Unauthorized, exchangeRes4.StatusCode);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task DbSigningKeys_Rotate_Allows_Inactive_Verification_And_Disable_Is_Immediate_401()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        static string? ReadKid(string jwt)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwt);
            return token.Header.Kid;
        }

        async Task<string> ExchangePlatformTokenAsync(HttpClient authnClient)
        {
            var exchangeRes = await authnClient.PostAsJsonAsync(
                "/api/v1/platform/auth/bootstrap/exchange",
                new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), role = "platform.super_admin", reason = "signing-key-test" },
                JsonOptions);
            if (exchangeRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await exchangeRes.Content.ReadAsStringAsync();
                Assert.Fail($"/platform/auth/bootstrap/exchange failed: {(int)exchangeRes.StatusCode} {exchangeRes.StatusCode}\n{debug}");
            }

            var body = await exchangeRes.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            Assert.NotNull(body);
            Assert.True(body!.Success);
            Assert.False(string.IsNullOrWhiteSpace(body.Data!.PlatformAccessToken));
            return body.Data!.PlatformAccessToken;
        }

        async Task<JwtSigningKeyRecord> RotateHmacAsync(HttpClient authzClient)
        {
            using var rotateReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/signing-keys/rotate")
            {
                Content = JsonContent.Create(new { algorithm = "HS256", bytes = 48, reason = "signing-key-test" }, options: JsonOptions),
            };
            var rotateRes = await authzClient.SendAsync(rotateReq);
            if (rotateRes.StatusCode != HttpStatusCode.Created)
            {
                var debug = await rotateRes.Content.ReadAsStringAsync();
                Assert.Fail($"/platform/signing-keys/rotate failed: {(int)rotateRes.StatusCode} {rotateRes.StatusCode}\n{debug}");
            }

            var rotateBody = await rotateRes.Content.ReadFromJsonAsync<ApiResponse<JwtSigningKeyRecord>>(JsonOptions);
            Assert.NotNull(rotateBody);
            Assert.True(rotateBody!.Success);
            Assert.NotNull(rotateBody.Data);
            Assert.False(string.IsNullOrWhiteSpace(rotateBody.Data!.Kid));
            return rotateBody.Data!;
        }

        async Task<HttpStatusCode> GetSigningKeysAsync(HttpClient authzClient, string bearer)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/platform/signing-keys");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            var res = await authzClient.SendAsync(req);
            return res.StatusCode;
        }

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);

            var authnClient = authnFactory.CreateClient();
            var authzClient = authzFactory.CreateClient();

            // Ensure DB exists / baseline seeded.
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "signing-key-tenant",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");
            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            Assert.Equal(HttpStatusCode.OK, bootstrapRes.StatusCode);

            // Token signed by legacy config key; used only to bootstrap key governance.
            var legacyPlatformToken = await ExchangePlatformTokenAsync(authnClient);
            authzClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", legacyPlatformToken);

            // Create first DB signing key.
            var key1 = await RotateHmacAsync(authzClient);

            // New token should now be signed by the DB active key.
            var token1 = await ExchangePlatformTokenAsync(authnClient);
            Assert.Equal(key1.Kid, ReadKid(token1));
            Assert.Equal(HttpStatusCode.OK, await GetSigningKeysAsync(authzClient, token1));

            // Rotate again: key1 becomes inactive; token1 should still be verifiable.
            authzClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token1);
            var key2 = await RotateHmacAsync(authzClient);
            Assert.NotEqual(key1.Kid, key2.Kid);

            var token2 = await ExchangePlatformTokenAsync(authnClient);
            Assert.Equal(key2.Kid, ReadKid(token2));
            Assert.Equal(HttpStatusCode.OK, await GetSigningKeysAsync(authzClient, token1));
            Assert.Equal(HttpStatusCode.OK, await GetSigningKeysAsync(authzClient, token2));

            // Disable key1: token1 should immediately become invalid (401), token2 remains valid.
            using var disableReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/platform/signing-keys/{Uri.EscapeDataString(key1.Kid)}/disable")
            {
                Content = JsonContent.Create(new { reason = "signing-key-test-disable" }, options: JsonOptions),
            };
            disableReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token2);
            var disableRes = await authzClient.SendAsync(disableReq);
            Assert.Equal(HttpStatusCode.OK, disableRes.StatusCode);

            Assert.Equal(HttpStatusCode.Unauthorized, await GetSigningKeysAsync(authzClient, token1));
            Assert.Equal(HttpStatusCode.OK, await GetSigningKeysAsync(authzClient, token2));
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task TenantToken_TokenVersion_Bumps_Immediately_Invalidate_Previously_Issued_Token_Is_401()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);

            var authnClient = authnFactory.CreateClient();
            var authzClient = authzFactory.CreateClient();

            // Initialize DB with a tenant.
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "tv-bump-tenant",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");

            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            Assert.Equal(HttpStatusCode.OK, bootstrapRes.StatusCode);

            var bootstrapBody = await bootstrapRes.Content.ReadFromJsonAsync<ApiResponse<BootstrapResult>>(JsonOptions);
            Assert.NotNull(bootstrapBody);
            Assert.True(bootstrapBody!.Success);
            var tenantId = bootstrapBody.Data!.TenantId;
            var ourSubject = bootstrapBody.Data!.OurSubject;

            async Task<string> LoginAsync()
            {
                using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
                {
                    Content = JsonContent.Create(new LoginRequest(Username: "admin", Password: "Passw0rd!"), options: JsonOptions),
                };
                loginReq.Headers.Add("X-Tenant-Id", tenantId.ToString());

                var loginRes = await authnClient.SendAsync(loginReq);
                Assert.Equal(HttpStatusCode.OK, loginRes.StatusCode);

                var loginBody = await loginRes.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
                Assert.NotNull(loginBody);
                Assert.True(loginBody!.Success);
                return loginBody.Data!.Tokens!.AccessToken;
            }

            async Task<HttpStatusCode> CallTenantProductsAsync(string accessToken)
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/products");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var res = await authzClient.SendAsync(req);
                return res.StatusCode;
            }

            var token1 = await LoginAsync();
            Assert.Equal(HttpStatusCode.OK, await CallTenantProductsAsync(token1));

            // Bump subject token version => old token must fail authentication.
            using (var scope = authzFactory.Services.CreateScope())
            {
                var subjects = scope.ServiceProvider.GetRequiredService<ISubjectRepository>();
                _ = await subjects.IncrementTokenVersionAsync(tenantId, ourSubject);
            }
            Assert.Equal(HttpStatusCode.Unauthorized, await CallTenantProductsAsync(token1));

            // Re-login to get a new token with updated subject_tv.
            var token2 = await LoginAsync();
            Assert.Equal(HttpStatusCode.OK, await CallTenantProductsAsync(token2));

            // Bump tenant token version => old token must fail authentication.
            using (var scope = authzFactory.Services.CreateScope())
            {
                var tenants = scope.ServiceProvider.GetRequiredService<ITenantRepository>();
                _ = await tenants.IncrementTokenVersionAsync(tenantId);
            }
            Assert.Equal(HttpStatusCode.Unauthorized, await CallTenantProductsAsync(token2));
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task Startup_FailFast_When_Permission_References_Missing_Product()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            var opts = new DbContextOptionsBuilder<SecurityDbContext>().UseSqlite(cs).Options;
            await using (var db = new SecurityDbContext(opts))
            {
                await db.Database.EnsureCreatedAsync();
                var now = DateTimeOffset.UtcNow;
                db.Permissions.Add(new Birdsoft.Security.Data.EfCore.Entities.PermissionEntity
                {
                    PermId = Guid.NewGuid(),
                    PermKey = "orders:read",
                    ProductKey = "missing_product",
                    Description = "broken",
                    CreatedAt = now,
                    UpdatedAt = now,
                });
                await db.SaveChangesAsync();
            }

            await Assert.ThrowsAnyAsync<Exception>(async () =>
            {
                await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);
                var client = authzFactory.CreateClient();
                _ = await client.GetAsync("/health");
            });
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    private sealed class TestAppLogger<T>(UnhandledExceptionCapture capture) : IAppLogger<T>
    {
        public bool IsEnabled(LogLevel level) => true;

        public void Log(LogLevel level, Exception? exception, string messageTemplate, params object?[] args)
        {
            if (level >= LogLevel.Error)
            {
                capture.Capture(exception, messageTemplate);
            }
        }
    }

    private sealed class AuthnApiFactory(string connectionString, string jwtIssuer, string jwtAudience, string jwtSigningKey) : WebApplicationFactory<Authn::Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");

            builder.ConfigureAppConfiguration((context, config) =>
            {
                var dict = new Dictionary<string, string?>
                {
                    ["Logging:LogLevel:Default"] = "Warning",
                    ["Logging:LogLevel:Microsoft"] = "Warning",
                    ["Logging:LogLevel:System"] = "Warning",
                    ["Logging:LogLevel:Microsoft.EntityFrameworkCore.Database.Command"] = "Warning",
                    ["Logging:LogLevel:Microsoft.AspNetCore.HttpsPolicy"] = "Error",

                    ["ConnectionStrings:SecurityDb"] = connectionString,

                    ["Bootstrap:Enabled"] = "true",
                    ["Bootstrap:Key"] = "test-bootstrap-key",

                    [$"{JwtOptions.SectionName}:Issuer"] = jwtIssuer,
                    [$"{JwtOptions.SectionName}:Audience"] = jwtAudience,
                    [$"{JwtOptions.SectionName}:SigningKey"] = jwtSigningKey,
                    [$"{JwtOptions.SectionName}:SigningAlgorithm"] = "HS256",
                    [$"{JwtOptions.SectionName}:AccessTokenMinutes"] = "5",
                    [$"{JwtOptions.SectionName}:RefreshTokenDays"] = "7",
                    [$"{JwtOptions.SectionName}:ClockSkewSeconds"] = "30",

                    ["Security:RefreshTokenHashing:Pepper"] = "bootstrap-tests-pepper",
                    ["Security:BootstrapKeyHashing:Pepper"] = "bootstrap-bootstrapkey-pepper",

                    ["Security:Environment:EnvironmentId"] = "test",
                    [$"{SecuritySafetyOptions.SectionName}:Enabled"] = "false",
                    [$"{SecuritySafetyOptions.SectionName}:RequireEnvironmentId"] = "false",
                    [$"{SecuritySafetyOptions.SectionName}:EnforceTenantJwtIsolation"] = "false",

                    // Password login is in-memory (option-driven). Bootstrap seeds the subject in DB,
                    // and we keep the same OurSubject here so login produces a token for that subject.
                    [$"{PasswordLoginOptions.SectionName}:Enabled"] = "true",
                    [$"{PasswordLoginOptions.SectionName}:Users:0:Username"] = "admin",
                    [$"{PasswordLoginOptions.SectionName}:Users:0:Password"] = "Passw0rd!",
                    [$"{PasswordLoginOptions.SectionName}:Users:0:OurSubject"] = DefaultAdminBootstrapIntegrationTests.DefaultAdminSubject.ToString(),
                };

                config.AddInMemoryCollection(dict);
            });

            builder.ConfigureServices(services =>
            {
                // Surface unhandled exceptions in tests even if the API returns a generic internal_error.
                services.AddSingleton<UnhandledExceptionCapture>();
                services.RemoveAll(typeof(IAppLogger<>));
                services.AddTransient(typeof(IAppLogger<>), typeof(TestAppLogger<>));

                // Force EF-backed stack even if Program.cs computed useEf=false before WebApplicationFactory
                // configuration is applied.
                services.RemoveAll<SecurityDbContext>();
                services.RemoveAll<DbContextOptions<SecurityDbContext>>();

                services.RemoveAll<IAuthEventStore>();
                services.RemoveAll<IAuthStateService>();
                services.RemoveAll<IExternalIdentityStore>();
                services.RemoveAll<ITenantRepository>();
                services.RemoveAll<ISubjectRepository>();
                services.RemoveAll<ISessionStore>();
                services.RemoveAll<ITokenService>();
                services.RemoveAll<Authn::Birdsoft.Security.Authentication.InMemoryTokenService>();

                services.RemoveAll<IAuthStateRepository>();
                services.RemoveAll<IRefreshTokenRepository>();
                services.RemoveAll<IExternalIdentityRepository>();
                services.RemoveAll<ILocalAccountRepository>();
                services.RemoveAll<IAccessTokenDenylistStore>();
                services.RemoveAll<IOidcProviderRegistry>();
                services.RemoveAll<IOidcProviderService>();

                services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(connectionString));
                services.AddSecurityEfCoreDataAccess();

                services.AddScoped<IAuthStateService, Authn::Birdsoft.Security.Authentication.Persistence.RepositoryAuthStateService>();
                services.AddScoped<IExternalIdentityStore, Authn::Birdsoft.Security.Authentication.Persistence.ExternalIdentityStoreFromRepository>();
                services.AddScoped<ITokenService, Authn::Birdsoft.Security.Authentication.Persistence.RepositoryTokenService>();
            });
        }
    }

    private sealed class AuthzApiFactory(string connectionString, string jwtIssuer, string jwtAudience, string jwtSigningKey) : WebApplicationFactory<Authz::Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");

            builder.ConfigureAppConfiguration((context, config) =>
            {
                var dict = new Dictionary<string, string?>
                {
                    ["Logging:LogLevel:Default"] = "Warning",
                    ["Logging:LogLevel:Microsoft"] = "Warning",
                    ["Logging:LogLevel:System"] = "Warning",
                    ["Logging:LogLevel:Microsoft.EntityFrameworkCore.Database.Command"] = "Warning",
                    ["Logging:LogLevel:Microsoft.AspNetCore.HttpsPolicy"] = "Error",

                    ["ConnectionStrings:SecurityDb"] = connectionString,

                    [$"{JwtOptions.SectionName}:Issuer"] = jwtIssuer,
                    [$"{JwtOptions.SectionName}:Audience"] = jwtAudience,
                    [$"{JwtOptions.SectionName}:SigningKey"] = jwtSigningKey,
                    [$"{JwtOptions.SectionName}:SigningAlgorithm"] = "HS256",
                    [$"{JwtOptions.SectionName}:ClockSkewSeconds"] = "30",

                    ["Security:BootstrapKeyHashing:Pepper"] = "bootstrap-bootstrapkey-pepper",

                    ["Security:Environment:EnvironmentId"] = "test",
                    [$"{SecuritySafetyOptions.SectionName}:Enabled"] = "false",
                    [$"{SecuritySafetyOptions.SectionName}:RequireEnvironmentId"] = "false",
                    [$"{SecuritySafetyOptions.SectionName}:EnforceTenantJwtIsolation"] = "false",
                };

                config.AddInMemoryCollection(dict);
            });

            builder.ConfigureServices(services =>
            {
                // Surface unhandled exceptions in tests even if the API returns a generic internal_error.
                services.AddSingleton<UnhandledExceptionCapture>();
                services.RemoveAll(typeof(IAppLogger<>));
                services.AddTransient(typeof(IAppLogger<>), typeof(TestAppLogger<>));

                // Force EF-backed stack even if Program.cs computed useEf=false before WebApplicationFactory
                // configuration is applied.
                services.RemoveAll<SecurityDbContext>();
                services.RemoveAll<DbContextOptions<SecurityDbContext>>();

                services.RemoveAll<ITenantRepository>();
                services.RemoveAll<ISubjectRepository>();
                services.RemoveAll<ISessionStore>();
                services.RemoveAll<IAuthEventStore>();
                services.RemoveAll<IAuthorizationDataStore>();
                services.RemoveAll<IAuthorizationAdminStore>();
                services.RemoveAll<IPermissionCatalogStore>();
                services.RemoveAll<ITenantEntitlementStore>();

                services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(connectionString));
                services.AddSecurityEfCoreDataAccess();
            });
        }
    }

    private static string CreateTempSqliteDbPath()
    {
        var root = Path.Combine(Path.GetTempPath(), "Birdsoft.Security.Bootstrap.Tests", "db");
        Directory.CreateDirectory(root);
        return Path.Combine(root, $"security-{Guid.NewGuid():N}.sqlite");
    }

    private sealed record BootstrapRequest(
        Guid? TenantId,
        string? TenantName,
        Guid? OurSubject,
        string Username,
        string Password,
        string? ProductKey,
        string? PermissionKey);

    private sealed record BootstrapResult(Guid TenantId, Guid OurSubject, string Username, string ProductKey, string PermissionKey);

    private sealed record TenantSetUserPermissionRequest(string PermissionKey, string? Reason);

    private sealed record PlatformBootstrapTokenRequest(Guid? OurSubject, string? Role, string? Reason);

    private sealed record PlatformBootstrapTokenResult(Guid OurSubject, string AccessToken, DateTimeOffset ExpiresAt);

    private sealed record PlatformBootstrapExchangeResult(
        Guid OurSubject,
        [property: System.Text.Json.Serialization.JsonPropertyName("platform_access_token")] string PlatformAccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
        [property: System.Text.Json.Serialization.JsonPropertyName("token_type")] string TokenType,
        [property: System.Text.Json.Serialization.JsonPropertyName("scope")] string Scope);

    [Fact]
    public async Task Platform_Role_Tiers_Enforce_Least_Privilege()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            var authnClient = authnFactory.CreateClient();

            // Initialize DB (tenant bootstrap) so platform APIs are EF-backed.
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "bootstrap-tenant",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");

            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            Assert.Equal(HttpStatusCode.OK, bootstrapRes.StatusCode);

            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);
            var authzClient = authzFactory.CreateClient();

            async Task<string> ExchangeAsync(string role)
            {
                using var platformReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/auth/bootstrap/exchange")
                {
                    Content = JsonContent.Create(new
                    {
                        bootstrap_key = "test-bootstrap-key",
                        ourSubject = Guid.NewGuid(),
                        role,
                        reason = "role-tier-test",
                    }, options: JsonOptions),
                };

                var res = await authnClient.SendAsync(platformReq);
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);

                var body = await res.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
                Assert.NotNull(body);
                Assert.True(body!.Success);
                Assert.NotNull(body.Data);
                Assert.False(string.IsNullOrWhiteSpace(body.Data!.PlatformAccessToken));
                return body.Data!.PlatformAccessToken;
            }

            var readonlyToken = await ExchangeAsync(PlatformRoles.ReadonlyAdmin);
            var opsToken = await ExchangeAsync(PlatformRoles.OpsAdmin);
            var superToken = await ExchangeAsync(PlatformRoles.SuperAdmin);

            // Disable ops admin and ensure existing token becomes invalid immediately.
            var opsSubject = Guid.NewGuid();
            _ = await ExchangeAsync(PlatformRoles.OpsAdmin);

            // Create admin record explicitly so we can update status/role later.
            using (var createAdmin = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/admins")
            {
                Content = JsonContent.Create(new { ourSubject = opsSubject, role = PlatformRoles.OpsAdmin, reason = "test" }, options: JsonOptions),
            })
            {
                createAdmin.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", superToken);
                var res = await authzClient.SendAsync(createAdmin);
                Assert.True(res.StatusCode is HttpStatusCode.Created or HttpStatusCode.Conflict);
            }

            // Mint a token for opsSubject (so it carries platform_admin_tv)
            using var platformReq2 = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/auth/bootstrap/exchange")
            {
                Content = JsonContent.Create(new { bootstrap_key = "test-bootstrap-key", ourSubject = opsSubject, role = PlatformRoles.OpsAdmin, reason = "tv" }, options: JsonOptions),
            };
            var platformRes2 = await authnClient.SendAsync(platformReq2);
            Assert.Equal(HttpStatusCode.OK, platformRes2.StatusCode);
            var platformBody2 = await platformRes2.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            Assert.NotNull(platformBody2);
            Assert.True(platformBody2!.Success);
            var opsSubjectToken = platformBody2.Data!.PlatformAccessToken;

            // Disable the ops admin
            using (var disableReq = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/platform/admins/{opsSubject}/status")
            {
                Content = JsonContent.Create(new { status = (int)PlatformAdminStatus.Disabled, reason = "disable" }, options: JsonOptions),
            })
            {
                disableReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", superToken);
                var res = await authzClient.SendAsync(disableReq);
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            }

            // Existing ops token should now be rejected
            using (var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/platform/products"))
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", opsSubjectToken);
                var res = await authzClient.SendAsync(req);
                Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
            }

            // Re-enable and change role to readonly -> old token should still be rejected due to version bump
            using (var enableReq = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/platform/admins/{opsSubject}/status")
            {
                Content = JsonContent.Create(new { status = (int)PlatformAdminStatus.Active, reason = "enable" }, options: JsonOptions),
            })
            {
                enableReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", superToken);
                var res = await authzClient.SendAsync(enableReq);
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            }

            using (var roleReq = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/platform/admins/{opsSubject}/role")
            {
                Content = JsonContent.Create(new { role = PlatformRoles.ReadonlyAdmin, reason = "role" }, options: JsonOptions),
            })
            {
                roleReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", superToken);
                var res = await authzClient.SendAsync(roleReq);
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            }

            using (var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/platform/products"))
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", opsSubjectToken);
                var res = await authzClient.SendAsync(req);
                Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
            }

            // Readonly: can read
            using (var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/platform/products"))
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", readonlyToken);
                var res = await authzClient.SendAsync(req);
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            }

            // Readonly: cannot write
            using (var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/products")
            {
                Content = JsonContent.Create(new { productKey = "ro-prod", displayName = "RO", reason = "ro" }, options: JsonOptions),
            })
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", readonlyToken);
                var res = await authzClient.SendAsync(req);
                Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
            }

            // Ops: can write products
            using (var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/products")
            {
                Content = JsonContent.Create(new { productKey = "ops-prod", displayName = "OPS", reason = "ops" }, options: JsonOptions),
            })
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", opsToken);
                var res = await authzClient.SendAsync(req);
                Assert.Equal(HttpStatusCode.Created, res.StatusCode);
            }

            // Ops: cannot revoke platform tokens
            using (var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/tokens/revoke")
            {
                Content = JsonContent.Create(new { reason = "ops" }, options: JsonOptions),
            })
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", opsToken);
                var res = await authzClient.SendAsync(req);
                Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
            }

            // Super: can revoke platform tokens
            using (var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/tokens/revoke")
            {
                Content = JsonContent.Create(new { reason = "super" }, options: JsonOptions),
            })
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", superToken);
                var res = await authzClient.SendAsync(req);
                Assert.Equal(HttpStatusCode.NoContent, res.StatusCode);
            }
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    private static string CreateExpiredPlatformJwt(string issuer, string audience, string signingKey)
    {
        var now = DateTimeOffset.UtcNow;
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)) { KeyId = "test-kid" };
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new("sub", Guid.NewGuid().ToString()),
            new(SecurityClaimTypes.OurSubject, Guid.NewGuid().ToString()),
            new(SecurityClaimTypes.TokenType, "platform_access"),
            new(SecurityClaimTypes.TokenPlane, "platform"),
            new(SecurityClaimTypes.Scope, "platform"),
            new(SecurityClaimTypes.PlatformTokenVersion, "1"),
            new(SecurityClaimTypes.Permissions, "platform.admin"),
        };

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: now.AddMinutes(-10).UtcDateTime,
            expires: now.AddMinutes(-1).UtcDateTime,
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    [Fact]
    public async Task EmptyDb_Bootstrap_DefaultAdmin_Can_Login_And_Manage_Tenant_Permissions()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            var authnClient = authnFactory.CreateClient();

            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "bootstrap-tenant",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");

            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            if (bootstrapRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await bootstrapRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/bootstrap failed: {(int)bootstrapRes.StatusCode} {bootstrapRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var bootstrapBody = await bootstrapRes.Content.ReadFromJsonAsync<ApiResponse<BootstrapResult>>(JsonOptions);
            Assert.NotNull(bootstrapBody);
            Assert.True(bootstrapBody!.Success);
            Assert.NotNull(bootstrapBody.Data);

            var tenantId = bootstrapBody.Data!.TenantId;
            var ourSubject = bootstrapBody.Data.OurSubject;
            Assert.NotEqual(Guid.Empty, tenantId);
            Assert.NotEqual(Guid.Empty, ourSubject);

            // Login via password (AuthN) to get a tenant token with security.admin scope.
            using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "admin", Password: "Passw0rd!")),
            };
            loginReq.Headers.Add("X-Tenant-Id", tenantId.ToString());

            var loginRes = await authnClient.SendAsync(loginReq);
            if (loginRes.StatusCode != HttpStatusCode.OK)
            {
                var debug = await loginRes.Content.ReadAsStringAsync();
                var capture = authnFactory.Services.GetRequiredService<UnhandledExceptionCapture>();
                var ex = capture.LastException;
                var exText = ex is null ? "<no captured exception>" : ex.ToString();
                Assert.Fail($"/api/v1/auth/password/login failed: {(int)loginRes.StatusCode} {loginRes.StatusCode}\n{debug}\n\nUnhandled: {exText}");
            }

            var loginBody = await loginRes.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(loginBody);
            Assert.True(loginBody!.Success);
            Assert.NotNull(loginBody.Data);
            Assert.Equal("success", loginBody.Data!.Status);
            Assert.NotNull(loginBody.Data.Tokens);

            var accessToken = loginBody.Data.Tokens!.AccessToken;
            Assert.False(string.IsNullOrWhiteSpace(accessToken));

            // Call tenant admin surface (AuthZ) using the minted token.
            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);
            var authzClient = authzFactory.CreateClient();

            using var listReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/permissions");
            listReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var listRes = await authzClient.SendAsync(listReq);
            Assert.Equal(HttpStatusCode.OK, listRes.StatusCode);

            // Grant a permission to the default admin (exercise management path).
            using var grantReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenant/users/{ourSubject}/permissions")
            {
                Content = JsonContent.Create(new TenantSetUserPermissionRequest(PermissionKey: "security.manage", Reason: "bootstrap-test")),
            };
            grantReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var grantRes = await authzClient.SendAsync(grantReq);
            Assert.Equal(HttpStatusCode.OK, grantRes.StatusCode);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task BootstrapKey_Can_Exchange_For_PlatformToken_And_Plane_Separation_Is_Enforced()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        var platformSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            var authnClient = authnFactory.CreateClient();

            // Initialize DB (tenant bootstrap) so we can mint a tenant token for separation tests.
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "bootstrap-tenant",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");

            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            Assert.Equal(HttpStatusCode.OK, bootstrapRes.StatusCode);

            var bootstrapBody = await bootstrapRes.Content.ReadFromJsonAsync<ApiResponse<BootstrapResult>>(JsonOptions);
            Assert.NotNull(bootstrapBody);
            Assert.True(bootstrapBody!.Success);
            Assert.NotNull(bootstrapBody.Data);

            var tenantId = bootstrapBody.Data!.TenantId;

            // Tenant token
            using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "admin", Password: "Passw0rd!")),
            };
            loginReq.Headers.Add("X-Tenant-Id", tenantId.ToString());

            var loginRes = await authnClient.SendAsync(loginReq);
            Assert.Equal(HttpStatusCode.OK, loginRes.StatusCode);

            var loginBody = await loginRes.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(loginBody);
            Assert.True(loginBody!.Success);
            Assert.NotNull(loginBody.Data);
            Assert.NotNull(loginBody.Data!.Tokens);
            var tenantAccessToken = loginBody.Data!.Tokens!.AccessToken;
            Assert.False(string.IsNullOrWhiteSpace(tenantAccessToken));

            // Platform token (bootstrap-key exchange)
            var platformReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/auth/bootstrap/exchange")
            {
                Content = JsonContent.Create(new { bootstrap_key = "test-bootstrap-key", ourSubject = platformSubject, reason = "integration-test" }, options: JsonOptions),
            };

            var platformRes = await authnClient.SendAsync(platformReq);
            Assert.Equal(HttpStatusCode.OK, platformRes.StatusCode);

            var platformBody = await platformRes.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            Assert.NotNull(platformBody);
            Assert.True(platformBody!.Success);
            Assert.NotNull(platformBody.Data);
            var platformAccessToken = platformBody.Data!.PlatformAccessToken;
            Assert.False(string.IsNullOrWhiteSpace(platformAccessToken));

            // Validate platform token shape (no tenant_id, token_plane=platform)
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(platformAccessToken);
            Assert.DoesNotContain(jwt.Claims, c => string.Equals(c.Type, SecurityClaimTypes.TenantId, StringComparison.Ordinal));
            Assert.Contains(jwt.Claims, c => string.Equals(c.Type, SecurityClaimTypes.TokenType, StringComparison.Ordinal) && string.Equals(c.Value, "platform_access", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(jwt.Claims, c => string.Equals(c.Type, SecurityClaimTypes.TokenPlane, StringComparison.Ordinal) && string.Equals(c.Value, "platform", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(jwt.Claims, c => string.Equals(c.Type, SecurityClaimTypes.Scope, StringComparison.Ordinal) && c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(s => string.Equals(s, "platform", StringComparison.OrdinalIgnoreCase)));
            Assert.True(jwt.Payload.TryGetValue(SecurityClaimTypes.Permissions, out var permsObj));
            var permsJson = JsonSerializer.Serialize(permsObj, JsonOptions);
            Assert.Contains("platform.admin", permsJson, StringComparison.OrdinalIgnoreCase);

            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);
            var authzClient = authzFactory.CreateClient();

            // Platform token can call platform management surface
            using var platformListReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/platform/products");
            platformListReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var platformListRes = await authzClient.SendAsync(platformListReq);
            Assert.Equal(HttpStatusCode.OK, platformListRes.StatusCode);

            // Platform token must be rejected by tenant admin surfaces
            using var tenantListReq1 = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/permissions");
            tenantListReq1.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var tenantListRes1 = await authzClient.SendAsync(tenantListReq1);
            Assert.Equal(HttpStatusCode.Forbidden, tenantListRes1.StatusCode);

            // Tenant token must be rejected by platform surfaces
            using var platformListReq2 = new HttpRequestMessage(HttpMethod.Get, "/api/v1/platform/products");
            platformListReq2.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantAccessToken);
            var platformListRes2 = await authzClient.SendAsync(platformListReq2);
            Assert.Equal(HttpStatusCode.Forbidden, platformListRes2.StatusCode);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task TenantAccessToken_Calling_PlatformOnly_Endpoint_Is_403_And_PlatformToken_Is_200()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            var authnClient = authnFactory.CreateClient();

            // Initialize DB so we can mint a tenant access token.
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "bootstrap-tenant",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");

            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            Assert.Equal(HttpStatusCode.OK, bootstrapRes.StatusCode);

            var bootstrapBody = await bootstrapRes.Content.ReadFromJsonAsync<ApiResponse<BootstrapResult>>(JsonOptions);
            Assert.NotNull(bootstrapBody);
            Assert.True(bootstrapBody!.Success);
            Assert.NotNull(bootstrapBody.Data);
            var tenantId = bootstrapBody.Data!.TenantId;

            // Tenant token.
            using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "admin", Password: "Passw0rd!")),
            };
            loginReq.Headers.Add("X-Tenant-Id", tenantId.ToString());

            var loginRes = await authnClient.SendAsync(loginReq);
            Assert.Equal(HttpStatusCode.OK, loginRes.StatusCode);

            var loginBody = await loginRes.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(loginBody);
            Assert.True(loginBody!.Success);
            Assert.NotNull(loginBody.Data);
            Assert.NotNull(loginBody.Data!.Tokens);
            var tenantAccessToken = loginBody.Data!.Tokens!.AccessToken;
            Assert.False(string.IsNullOrWhiteSpace(tenantAccessToken));

            // Platform token.
            using var platformReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/auth/bootstrap/exchange")
            {
                Content = JsonContent.Create(new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.NewGuid(), reason = "regression" }, options: JsonOptions),
            };

            var platformRes = await authnClient.SendAsync(platformReq);
            Assert.Equal(HttpStatusCode.OK, platformRes.StatusCode);

            var platformBody = await platformRes.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            Assert.NotNull(platformBody);
            Assert.True(platformBody!.Success);
            Assert.NotNull(platformBody.Data);
            var platformAccessToken = platformBody.Data!.PlatformAccessToken;
            Assert.False(string.IsNullOrWhiteSpace(platformAccessToken));

            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);
            var authzClient = authzFactory.CreateClient();

            // Tenant token must be rejected by a platform-only endpoint with 403 Forbidden (not 401 Unauthorized).
            using (var platformReqTenant = new HttpRequestMessage(HttpMethod.Get, "/api/v1/platform/products"))
            {
                platformReqTenant.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantAccessToken);
                var res = await authzClient.SendAsync(platformReqTenant);
                Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
            }

            // Platform token can call the same endpoint.
            using (var platformReqPlatform = new HttpRequestMessage(HttpMethod.Get, "/api/v1/platform/products"))
            {
                platformReqPlatform.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
                var res = await authzClient.SendAsync(platformReqPlatform);
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            }
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task Platform_Crud_Hardening_Works_And_TenantProducts_Reflect_Updates()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            var authnClient = authnFactory.CreateClient();

            // Initialize DB and mint a tenant token.
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "bootstrap-tenant",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");
            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            Assert.Equal(HttpStatusCode.OK, bootstrapRes.StatusCode);

            var bootstrapBody = await bootstrapRes.Content.ReadFromJsonAsync<ApiResponse<BootstrapResult>>(JsonOptions);
            Assert.NotNull(bootstrapBody);
            Assert.True(bootstrapBody!.Success);
            Assert.NotNull(bootstrapBody.Data);
            var tenantId = bootstrapBody.Data!.TenantId;

            using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "admin", Password: "Passw0rd!")),
            };
            loginReq.Headers.Add("X-Tenant-Id", tenantId.ToString());

            var loginRes = await authnClient.SendAsync(loginReq);
            Assert.Equal(HttpStatusCode.OK, loginRes.StatusCode);

            var loginBody = await loginRes.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(loginBody);
            Assert.True(loginBody!.Success);
            Assert.NotNull(loginBody.Data);
            Assert.NotNull(loginBody.Data!.Tokens);
            var tenantAccessToken = loginBody.Data!.Tokens!.AccessToken;

            // Mint platform token.
            var platformReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/auth/bootstrap/exchange")
            {
                Content = JsonContent.Create(new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "phase1" }, options: JsonOptions),
            };

            var platformRes = await authnClient.SendAsync(platformReq);
            Assert.Equal(HttpStatusCode.OK, platformRes.StatusCode);

            var platformBody = await platformRes.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            Assert.NotNull(platformBody);
            Assert.True(platformBody!.Success);
            Assert.NotNull(platformBody.Data);
            var platformAccessToken = platformBody.Data!.PlatformAccessToken;

            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);
            var authzClient = authzFactory.CreateClient();

            // Platform: create product
            var productKey = "reporting";
            using var createProductReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/products")
            {
                Content = JsonContent.Create(new { productKey, displayName = "Reporting", description = "phase1", status = (int)ProductStatus.Enabled, reason = "phase1" }, options: JsonOptions),
            };
            createProductReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var createProductRes = await authzClient.SendAsync(createProductReq);
            Assert.Equal(HttpStatusCode.Created, createProductRes.StatusCode);

            // Platform: create permission (FK to product)
            var permKey = "reporting.view";
            using var createPermReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/permissions")
            {
                Content = JsonContent.Create(new { permissionKey = permKey, productKey, description = "view reports", reason = "phase1" }, options: JsonOptions),
            };
            createPermReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var createPermRes = await authzClient.SendAsync(createPermReq);
            Assert.Equal(HttpStatusCode.Created, createPermRes.StatusCode);

            // Platform: permission must reject unknown productKey
            using var badPermReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/permissions")
            {
                Content = JsonContent.Create(new { permissionKey = "bad.perm", productKey = "does_not_exist", description = "x" }, options: JsonOptions),
            };
            badPermReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var badPermRes = await authzClient.SendAsync(badPermReq);
            Assert.Equal(HttpStatusCode.NotFound, badPermRes.StatusCode);

            // Platform: create a second tenant
            var newTenantId = Guid.NewGuid();
            using var createTenantReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/tenants")
            {
                Content = JsonContent.Create(new { tenantId = newTenantId, name = "phase1-tenant", status = (int)TenantStatus.Active, reason = "phase1" }, options: JsonOptions),
            };
            createTenantReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var createTenantRes = await authzClient.SendAsync(createTenantReq);
            Assert.Equal(HttpStatusCode.Created, createTenantRes.StatusCode);

            // Platform: grant entitlement via tenant entitlement create (alias endpoint)
            var startAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            var endAt = DateTimeOffset.UtcNow.AddDays(7);
            var planJson = "{\"tier\":\"gold\"}";
            using var createTpReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/platform/tenants/{tenantId}/entitlements")
            {
                Content = JsonContent.Create(new { productKey, status = (int)TenantProductStatus.Enabled, startAt, endAt, planJson, reason = "phase1" }, options: JsonOptions),
            };
            createTpReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var createTpRes = await authzClient.SendAsync(createTpReq);
            Assert.Equal(HttpStatusCode.Created, createTpRes.StatusCode);

            // Tenant: /tenant/products must reflect new entitlement immediately
            using var tenantList1 = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/products");
            tenantList1.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantAccessToken);
            var tenantListRes1 = await authzClient.SendAsync(tenantList1);
            Assert.Equal(HttpStatusCode.OK, tenantListRes1.StatusCode);

            static bool ContainsProductKey(string json, string expectedKey)
            {
                using var doc = JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                {
                    return false;
                }

                foreach (var item in data.EnumerateArray())
                {
                    if (item.TryGetProperty("productKey", out var pk) && pk.ValueKind == JsonValueKind.String)
                    {
                        if (string.Equals(pk.GetString(), expectedKey, StringComparison.Ordinal))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }

            var tenantListJson1 = await tenantListRes1.Content.ReadAsStringAsync();
            Assert.True(ContainsProductKey(tenantListJson1, productKey));

            // Platform: disabling product must override a still-enabled tenant entitlement immediately
            using var disableProductReq = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/platform/products/{productKey}")
            {
                Content = JsonContent.Create(new { status = (int)ProductStatus.Disabled, reason = "disable product" }, options: JsonOptions),
            };
            disableProductReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var disableProductRes = await authzClient.SendAsync(disableProductReq);
            Assert.Equal(HttpStatusCode.OK, disableProductRes.StatusCode);

            using var tenantListProductDisabled = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/products");
            tenantListProductDisabled.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantAccessToken);
            var tenantListProductDisabledRes = await authzClient.SendAsync(tenantListProductDisabled);
            Assert.Equal(HttpStatusCode.OK, tenantListProductDisabledRes.StatusCode);
            var tenantListProductDisabledJson = await tenantListProductDisabledRes.Content.ReadAsStringAsync();
            Assert.False(ContainsProductKey(tenantListProductDisabledJson, productKey));

            // Platform: re-enable product, entitlement should become effective again immediately
            using var enableProductReq = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/platform/products/{productKey}")
            {
                Content = JsonContent.Create(new { status = (int)ProductStatus.Enabled, reason = "re-enable product" }, options: JsonOptions),
            };
            enableProductReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var enableProductRes = await authzClient.SendAsync(enableProductReq);
            Assert.Equal(HttpStatusCode.OK, enableProductRes.StatusCode);

            using var tenantListProductEnabled = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/products");
            tenantListProductEnabled.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantAccessToken);
            var tenantListProductEnabledRes = await authzClient.SendAsync(tenantListProductEnabled);
            Assert.Equal(HttpStatusCode.OK, tenantListProductEnabledRes.StatusCode);
            var tenantListProductEnabledJson = await tenantListProductEnabledRes.Content.ReadAsStringAsync();
            Assert.True(ContainsProductKey(tenantListProductEnabledJson, productKey));

            // Platform: disable entitlement
            using var updateTpReq = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/platform/tenants/{tenantId}/entitlements/{productKey}")
            {
                Content = JsonContent.Create(new { status = (int)TenantProductStatus.Disabled, reason = "disable" }, options: JsonOptions),
            };
            updateTpReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var updateTpRes = await authzClient.SendAsync(updateTpReq);
            Assert.Equal(HttpStatusCode.OK, updateTpRes.StatusCode);

            // Platform: endAt/planJson must not change when omitted
            using var getTpReq = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/platform/tenants/{tenantId}/entitlements/{productKey}");
            getTpReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var getTpRes = await authzClient.SendAsync(getTpReq);
            Assert.Equal(HttpStatusCode.OK, getTpRes.StatusCode);

            var getTpJson = await getTpRes.Content.ReadAsStringAsync();
            using (var doc = JsonDocument.Parse(getTpJson))
            {
                Assert.True(doc.RootElement.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.True);
                Assert.True(doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object);

                Assert.True(data.TryGetProperty("endAt", out var endAtEl));
                var endAtFromApi = endAtEl.GetDateTimeOffset();
                Assert.Equal(endAt.ToUnixTimeSeconds(), endAtFromApi.ToUnixTimeSeconds());

                Assert.True(data.TryGetProperty("planJson", out var planJsonEl));
                Assert.Equal(planJson, planJsonEl.GetString());
            }

            // Tenant: /tenant/products must no longer include it
            using var tenantList2 = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/products");
            tenantList2.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantAccessToken);
            var tenantListRes2 = await authzClient.SendAsync(tenantList2);
            Assert.Equal(HttpStatusCode.OK, tenantListRes2.StatusCode);

            var tenantListJson2 = await tenantListRes2.Content.ReadAsStringAsync();
            Assert.False(ContainsProductKey(tenantListJson2, productKey));

            // Tenant token must be forbidden from platform endpoints
            using var forbiddenReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/platform/tenants");
            forbiddenReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantAccessToken);
            var forbiddenRes = await authzClient.SendAsync(forbiddenReq);
            Assert.Equal(HttpStatusCode.Forbidden, forbiddenRes.StatusCode);

            // Platform: disabling a tenant must invalidate the existing tenant token immediately
            using var disableTenantReq = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/platform/tenants/{tenantId}")
            {
                Content = JsonContent.Create(new { status = (int)TenantStatus.Suspended, reason = "disable tenant" }, options: JsonOptions),
            };
            disableTenantReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var disableTenantRes = await authzClient.SendAsync(disableTenantReq);
            Assert.Equal(HttpStatusCode.OK, disableTenantRes.StatusCode);

            using var tenantListAfterDisable = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/products");
            tenantListAfterDisable.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantAccessToken);
            var tenantListAfterDisableRes = await authzClient.SendAsync(tenantListAfterDisable);
            Assert.Equal(HttpStatusCode.Unauthorized, tenantListAfterDisableRes.StatusCode);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }

    [Fact]
    public async Task Platform_Update_Whitespace_Fields_Do_Not_Clear_Descriptions()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        const string issuer = "https://bootstrap.test";
        const string audience = "service";
        const string signingKey = "dev-signing-key-123456789012345678901234567890";

        try
        {
            await using var authnFactory = new AuthnApiFactory(cs, issuer, audience, signingKey);
            var authnClient = authnFactory.CreateClient();

            // Initialize DB.
            var bootstrapReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/bootstrap")
            {
                Content = JsonContent.Create(new BootstrapRequest(
                    TenantId: null,
                    TenantName: "bootstrap-tenant",
                    OurSubject: DefaultAdminSubject,
                    Username: "admin",
                    Password: "Passw0rd!",
                    ProductKey: "security",
                    PermissionKey: "security.manage"), options: JsonOptions),
            };
            bootstrapReq.Headers.Add("X-Bootstrap-Key", "test-bootstrap-key");
            var bootstrapRes = await authnClient.SendAsync(bootstrapReq);
            Assert.Equal(HttpStatusCode.OK, bootstrapRes.StatusCode);

            // Mint platform token.
            var platformReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/auth/bootstrap/exchange")
            {
                Content = JsonContent.Create(new { bootstrap_key = "test-bootstrap-key", ourSubject = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), reason = "phase1" }, options: JsonOptions),
            };
            var platformRes = await authnClient.SendAsync(platformReq);
            Assert.Equal(HttpStatusCode.OK, platformRes.StatusCode);

            var platformBody = await platformRes.Content.ReadFromJsonAsync<ApiResponse<PlatformBootstrapExchangeResult>>(JsonOptions);
            Assert.NotNull(platformBody);
            Assert.True(platformBody!.Success);
            Assert.NotNull(platformBody.Data);
            var platformAccessToken = platformBody.Data!.PlatformAccessToken;

            await using var authzFactory = new AuthzApiFactory(cs, issuer, audience, signingKey);
            var authzClient = authzFactory.CreateClient();

            // Create product
            var productKey = "billing";
            using var createProductReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/products")
            {
                Content = JsonContent.Create(new { productKey, displayName = "Billing", description = "orig", status = (int)ProductStatus.Enabled, reason = "phase1" }, options: JsonOptions),
            };
            createProductReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var createProductRes = await authzClient.SendAsync(createProductReq);
            Assert.Equal(HttpStatusCode.Created, createProductRes.StatusCode);

            // Update with whitespace-only fields (must not clear/change)
            using var updateProductReq = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/platform/products/{productKey}")
            {
                Content = JsonContent.Create(new { displayName = "   ", description = "   ", reason = "noop" }, options: JsonOptions),
            };
            updateProductReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var updateProductRes = await authzClient.SendAsync(updateProductReq);
            Assert.Equal(HttpStatusCode.OK, updateProductRes.StatusCode);

            using var getProductReq = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/platform/products/{productKey}");
            getProductReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var getProductRes = await authzClient.SendAsync(getProductReq);
            Assert.Equal(HttpStatusCode.OK, getProductRes.StatusCode);

            var getProductJson = await getProductRes.Content.ReadAsStringAsync();
            using (var doc = JsonDocument.Parse(getProductJson))
            {
                Assert.True(doc.RootElement.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.True);
                Assert.True(doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object);
                Assert.Equal("Billing", data.GetProperty("displayName").GetString());
                Assert.Equal("orig", data.GetProperty("description").GetString());
            }

            // Create permission
            var permKey = "billing.view";
            using var createPermReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/platform/permissions")
            {
                Content = JsonContent.Create(new { permissionKey = permKey, productKey, description = "orig", reason = "phase1" }, options: JsonOptions),
            };
            createPermReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var createPermRes = await authzClient.SendAsync(createPermReq);
            Assert.Equal(HttpStatusCode.Created, createPermRes.StatusCode);

            // Update permission with whitespace-only description (must not clear/change)
            using var updatePermReq = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/platform/permissions/{permKey}")
            {
                Content = JsonContent.Create(new { description = "   ", reason = "noop" }, options: JsonOptions),
            };
            updatePermReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var updatePermRes = await authzClient.SendAsync(updatePermReq);
            Assert.Equal(HttpStatusCode.OK, updatePermRes.StatusCode);

            using var getPermReq = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/platform/permissions/{permKey}");
            getPermReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", platformAccessToken);
            var getPermRes = await authzClient.SendAsync(getPermReq);
            Assert.Equal(HttpStatusCode.OK, getPermRes.StatusCode);

            var getPermJson = await getPermRes.Content.ReadAsStringAsync();
            using (var doc = JsonDocument.Parse(getPermJson))
            {
                Assert.True(doc.RootElement.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.True);
                Assert.True(doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object);
                Assert.Equal("orig", data.GetProperty("description").GetString());
            }
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { /* best-effort */ }
            }
        }
    }
}
