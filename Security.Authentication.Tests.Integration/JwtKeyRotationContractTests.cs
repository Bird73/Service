namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public sealed class JwtKeyRotationContractTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static IReadOnlyDictionary<string, string?> CreateKeyRingConfig(
        string activeKid,
        params (string kid, string symmetricKey, int status)[] keys)
    {
        var dict = new Dictionary<string, string?>
        {
            ["Security:Jwt:KeyRing:ActiveSigningKid"] = activeKid,
        };

        for (var i = 0; i < keys.Length; i++)
        {
            var (kid, symmetricKey, status) = keys[i];
            dict[$"Security:Jwt:KeyRing:Keys:{i}:Kid"] = kid;
            dict[$"Security:Jwt:KeyRing:Keys:{i}:Algorithm"] = "HS256";
            dict[$"Security:Jwt:KeyRing:Keys:{i}:SymmetricKey"] = symmetricKey;
            dict[$"Security:Jwt:KeyRing:Keys:{i}:Status"] = status.ToString();
        }

        return dict;
    }

    private static async Task<string> IssueAccessTokenAsync(AuthenticationApiFactory factory, Guid tenantId, Guid ourSubject)
    {
        using var scope = factory.Services.CreateScope();
        var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var pair = await tokens.GenerateTokensAsync(tenantId, ourSubject);
        return pair.AccessToken;
    }

    private static Task<HttpResponseMessage> PostRevokeAllAsync(HttpClient client, Guid tenantId, string accessToken)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/token/revoke")
        {
            Content = JsonContent.Create(new TokenRevokeRequest(RefreshToken: null, AllDevices: true)),
        };
        req.Headers.Add("X-Tenant-Id", tenantId.ToString());
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client.SendAsync(req);
    }

    private static string CreateHs256AccessToken(
        Guid tenantId,
        Guid ourSubject,
        string issuer,
        string audience,
        string kid,
        string symmetricKey,
        long nowUnixSeconds,
        long lifetimeSeconds)
    {
        var header = new Dictionary<string, object?>
        {
            ["alg"] = "HS256",
            ["typ"] = "JWT",
            ["kid"] = kid,
        };

        var jti = Guid.NewGuid().ToString("N");

        var payload = new Dictionary<string, object?>
        {
            ["iss"] = issuer,
            ["aud"] = audience,
            ["sub"] = ourSubject.ToString(),
            [SecurityClaimTypes.TenantId] = tenantId.ToString(),
            [SecurityClaimTypes.Jti] = jti,
            ["nbf"] = nowUnixSeconds,
            ["iat"] = nowUnixSeconds,
            ["exp"] = nowUnixSeconds + lifetimeSeconds,
        };

        var headerJson = JsonSerializer.Serialize(header, JsonOptions);
        var payloadJson = JsonSerializer.Serialize(payload, JsonOptions);

        var headerB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));

        var keyBytes = Encoding.UTF8.GetBytes(symmetricKey);
        return ReSignHs256(headerB64, payloadB64, keyBytes);
    }

    private static string? TryGetHeaderString(string jwt, string propertyName)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        var headerJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[0]));
        using var doc = JsonDocument.Parse(headerJson);
        return doc.RootElement.TryGetProperty(propertyName, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString()
            : null;
    }

    private static string ReSignHs256(string headerB64, string payloadB64, byte[] key)
    {
        var signingInput = $"{headerB64}.{payloadB64}";
        using var hmac = new HMACSHA256(key);
        var sig = hmac.ComputeHash(Encoding.ASCII.GetBytes(signingInput));
        var sigB64 = Base64UrlEncoder.Encode(sig);
        return $"{signingInput}.{sigB64}";
    }

    private static string RewriteHeaderAndResignHs256(string jwt, Func<Dictionary<string, object?>, Dictionary<string, object?>> mutateHeader, string symmetricKey)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new InvalidOperationException("Invalid JWT format.");
        }

        var headerJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[0]));
        using var doc = JsonDocument.Parse(headerJson);

        var header = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            header[p.Name] = p.Value.ValueKind switch
            {
                JsonValueKind.String => p.Value.GetString(),
                JsonValueKind.Number => p.Value.TryGetInt64(out var l) ? l : p.Value.GetDouble(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Null => null,
                _ => p.Value.GetRawText(),
            };
        }

        header = mutateHeader(header);

        var newHeaderJson = JsonSerializer.Serialize(header, JsonOptions);
        var newHeaderB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(newHeaderJson));
        var payloadB64 = parts[1];
        var keyBytes = Encoding.UTF8.GetBytes(symmetricKey);
        return ReSignHs256(newHeaderB64, payloadB64, keyBytes);
    }

    [Fact]
    public async Task Issuance_Includes_Kid_Header_When_Using_KeyRing()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var key = "k-secret-123456789012345678901234567890";

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            JwtSigningKey = "legacy-unused-when-keyring-present",
            ExtraConfiguration = CreateKeyRingConfig(
                activeKid: "k1",
                (kid: "k1", symmetricKey: key, status: 0)),
        });

        var token = await IssueAccessTokenAsync(factory, tenantId, ourSubject);
        Assert.Equal("k1", TryGetHeaderString(token, "kid"));
    }

    [Fact]
    public async Task Rotation_Coexistence_OldToken_Valid_When_OldKey_Present()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var kOld = "old-secret-123456789012345678901234567890";
        var kNew = "new-secret-123456789012345678901234567890";

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var oldToken = CreateHs256AccessToken(
            tenantId,
            ourSubject,
            issuer: "https://security.test",
            audience: "service",
            kid: "k1",
            symmetricKey: kOld,
            nowUnixSeconds: now,
            lifetimeSeconds: 300);

        using var factoryValidate = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            JwtSigningKey = "legacy-unused-when-keyring-present",
            ExtraConfiguration = CreateKeyRingConfig(
                activeKid: "k2",
                (kid: "k1", symmetricKey: kOld, status: 1), // retired but still valid for verification
                (kid: "k2", symmetricKey: kNew, status: 0)),
        });

        using var client = factoryValidate.CreateClient();
        var res = await PostRevokeAllAsync(client, tenantId, oldToken);

        // Token should still validate; revoke may still succeed even without refresh token.
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<TokenRevokeResponse>>(JsonOptions);
        Assert.NotNull(body);
        Assert.True(body!.Success);
    }

    [Fact]
    public async Task Rotation_After_OldKey_Removed_OldToken_InvalidToken()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var kOld = "old-secret-123456789012345678901234567890";
        var kNew = "new-secret-123456789012345678901234567890";

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var oldToken = CreateHs256AccessToken(
            tenantId,
            ourSubject,
            issuer: "https://security.test",
            audience: "service",
            kid: "k1",
            symmetricKey: kOld,
            nowUnixSeconds: now,
            lifetimeSeconds: 300);

        using var factoryValidate = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            JwtSigningKey = "legacy-unused-when-keyring-present",
            ExtraConfiguration = CreateKeyRingConfig(
                activeKid: "k2",
                (kid: "k2", symmetricKey: kNew, status: 0)),
        });

        using var client = factoryValidate.CreateClient();
        var res = await PostRevokeAllAsync(client, tenantId, oldToken);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.Equal("invalid_token", body.Error!.Code);
    }

    [Fact]
    public async Task Kid_Missing_Fails_InvalidToken()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var key = "k-secret-123456789012345678901234567890";

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            JwtSigningKey = "legacy-unused-when-keyring-present",
            ExtraConfiguration = CreateKeyRingConfig(
                activeKid: "k1",
                (kid: "k1", symmetricKey: key, status: 0)),
        });

        var token = await IssueAccessTokenAsync(factory, tenantId, ourSubject);
        var noKid = RewriteHeaderAndResignHs256(token, h =>
        {
            h.Remove("kid");
            return h;
        }, key);

        using var client = factory.CreateClient();
        var res = await PostRevokeAllAsync(client, tenantId, noKid);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.Equal("invalid_token", body.Error!.Code);
    }

    [Fact]
    public async Task Kid_Unknown_Fails_InvalidToken()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var key = "k-secret-123456789012345678901234567890";

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            JwtSigningKey = "legacy-unused-when-keyring-present",
            ExtraConfiguration = CreateKeyRingConfig(
                activeKid: "k1",
                (kid: "k1", symmetricKey: key, status: 0)),
        });

        var token = await IssueAccessTokenAsync(factory, tenantId, ourSubject);
        var unknownKid = RewriteHeaderAndResignHs256(token, h =>
        {
            h["kid"] = "unknown";
            return h;
        }, key);

        using var client = factory.CreateClient();
        var res = await PostRevokeAllAsync(client, tenantId, unknownKid);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.Equal("invalid_token", body.Error!.Code);
    }
}
