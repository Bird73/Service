namespace Birdsoft.Security.Authentication.Bootstrap;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Audit;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Abstractions.Observability.Correlation;
using Birdsoft.Security.Authentication;
using Birdsoft.Security.Authentication.Jwt;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class BootstrapEndpoints
{
    private const string BootstrapKeyHeaderName = "X-Bootstrap-Key";

    public static RouteGroupBuilder MapBootstrapEndpoints(this RouteGroupBuilder api)
    {
        api.MapPost("/bootstrap", BootstrapAsync);
        api.MapPost("/platform/bootstrap/token", BootstrapPlatformTokenAsync);
        // V19: platform bootstrap exchange (preferred)
        api.MapPost("/platform/auth/bootstrap/exchange", BootstrapPlatformTokenExchangeAsync);
        return api;
    }

    internal sealed record BootstrapRequest(
        Guid? TenantId,
        string? TenantName,
        Guid? OurSubject,
        string Username,
        string Password,
        string? ProductKey,
        string? PermissionKey);

    internal sealed record BootstrapResult(
        Guid TenantId,
        Guid OurSubject,
        string Username,
        string ProductKey,
        string PermissionKey);

    internal sealed record PlatformBootstrapTokenRequest(
        Guid? OurSubject,
        string? Role,
        string? Reason);

    internal sealed record PlatformBootstrapTokenResult(
        Guid OurSubject,
        string AccessToken,
        DateTimeOffset ExpiresAt);

    internal sealed record PlatformBootstrapExchangeRequest(
        [property: System.Text.Json.Serialization.JsonPropertyName("bootstrap_key")] string? BootstrapKey,
        Guid? OurSubject,
        string? Role,
        string? Reason);

    internal sealed record PlatformBootstrapExchangeResult(
        Guid OurSubject,
        [property: System.Text.Json.Serialization.JsonPropertyName("platform_access_token")] string PlatformAccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
        [property: System.Text.Json.Serialization.JsonPropertyName("token_type")] string TokenType,
        [property: System.Text.Json.Serialization.JsonPropertyName("scope")] string Scope);

    private static IReadOnlyDictionary<string, string[]> SingleField(string field, string message)
        => new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase) { [field] = [message] };

    private static bool HasValidBootstrapKey(IConfiguration config, string? providedKey)
    {
        // Allow rotation via Bootstrap:Keys (array) while keeping Bootstrap:Key for backwards compatibility.
        var keys = config.GetSection("Bootstrap:Keys").Get<string[]>()
            ?? (string.IsNullOrWhiteSpace(config["Bootstrap:Key"]) ? null : [config["Bootstrap:Key"]!]);

        if (keys is null || keys.Length == 0 || keys.All(string.IsNullOrWhiteSpace))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(providedKey))
        {
            return false;
        }

        return keys.Any(k => !string.IsNullOrWhiteSpace(k) && string.Equals(k, providedKey, StringComparison.Ordinal));
    }

    private static string? TryGetBootstrapKeyFromHeader(HttpContext http)
    {
        var providedKey = http.Request.Headers[BootstrapKeyHeaderName].ToString();
        return string.IsNullOrWhiteSpace(providedKey) ? null : providedKey;
    }

    private static async Task<bool> HasValidBootstrapKeyAsync(HttpContext http, IConfiguration config, string? providedKey, CancellationToken ct)
    {
        var store = http.RequestServices.GetService<IBootstrapKeyStore>();
        if (store is not null)
        {
            if (await store.HasAnyAsync(ct))
            {
                return await store.ValidateAsync(providedKey ?? string.Empty, DateTimeOffset.UtcNow, ct);
            }
        }

        return HasValidBootstrapKey(config, providedKey);
    }

    private static string ComputeHmacSha256(string input, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        var sig = hmac.ComputeHash(Encoding.ASCII.GetBytes(input));
        return Base64Url.Encode(sig);
    }

    private static string Sign(string signingInput, IJwtKeyProvider keys)
    {
        if (keys.Algorithm.Equals("RS256", StringComparison.OrdinalIgnoreCase))
        {
            var rsa = keys.GetRsaPrivateKey();
            if (rsa is null)
            {
                throw new InvalidOperationException("RS256 requires an RSA private key.");
            }

            var sig = rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Base64Url.Encode(sig);
        }

        var key = keys.GetSymmetricKeyBytes();
        if (key is null || key.Length == 0)
        {
            throw new InvalidOperationException("HMAC signing requires JwtOptions.SigningKey.");
        }

        return ComputeHmacSha256(signingInput, key);
    }

    private static (string token, DateTimeOffset expiresAt) CreatePlatformAccessToken(
        IJwtKeyProvider keys,
        JwtOptions opts,
        SecurityEnvironmentOptions env,
        Guid ourSubject,
        string platformRole,
        long platformAdminTokenVersion,
        long platformTokenVersion)
    {
        var now = DateTimeOffset.UtcNow;
        // Governance surface: keep platform tokens short-lived.
        // Allow config to shorten, but hard-cap it.
        var minutes = Math.Clamp(opts.PlatformAccessTokenMinutes, 1, 15);
        var exp = now.AddMinutes(minutes);

        var alg = string.IsNullOrWhiteSpace(opts.SigningAlgorithm) ? keys.Algorithm : opts.SigningAlgorithm.Trim();
        var kid = !string.IsNullOrWhiteSpace(opts.Kid) ? opts.Kid!.Trim() : keys.Kid;

        var header = new Dictionary<string, object?>
        {
            ["typ"] = "JWT",
            ["alg"] = alg,
            ["kid"] = kid,
        };

        var eff = JwtTenantResolution.Resolve(opts, Guid.Empty);
        var iss = JwtTenantResolution.ApplyEnvironmentSuffix(eff.Issuer, env);
        var aud = JwtTenantResolution.ApplyEnvironmentSuffix(eff.Audience, env);

        var scopes = new[] { "platform" };

        static string[] PermissionsForRole(string role)
        {
            if (string.Equals(role, PlatformRoles.SuperAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(role, PlatformRoles.LegacyPlatformAdmin, StringComparison.OrdinalIgnoreCase))
            {
                return
                [
                    "platform.admin",
                    "platform.tenants.read",
                    "platform.tenants.write",
                    "platform.products.read",
                    "platform.products.write",
                    "platform.entitlements.read",
                    "platform.entitlements.write",
                    "platform.permissions.read",
                    "platform.permissions.write",
                    "platform.audit.read",
                    "platform.tokens.write",
                ];
            }

            if (string.Equals(role, PlatformRoles.OpsAdmin, StringComparison.OrdinalIgnoreCase))
            {
                return
                [
                    "platform.tenants.read",
                    "platform.tenants.write",
                    "platform.products.read",
                    "platform.products.write",
                    "platform.entitlements.read",
                    "platform.entitlements.write",
                    "platform.permissions.read",
                    "platform.permissions.write",
                    "platform.audit.read",
                ];
            }

            // readonly
            return
            [
                "platform.tenants.read",
                "platform.products.read",
                "platform.entitlements.read",
                "platform.permissions.read",
                "platform.audit.read",
            ];
        }

        var roles = new[] { platformRole };
        var permissions = PermissionsForRole(platformRole);

        var payload = new Dictionary<string, object?>
        {
            ["iss"] = iss,
            ["aud"] = aud,
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = now.ToUnixTimeSeconds(),
            [TokenConstants.TokenFormatVersionClaim] = TokenConstants.TokenFormatVersion,
            [SecurityClaimTypes.Jti] = Guid.NewGuid().ToString("N"),
            ["sub"] = ourSubject.ToString(),
            [SecurityClaimTypes.OurSubject] = ourSubject.ToString(),
            [SecurityClaimTypes.TokenType] = "platform_access",
            [SecurityClaimTypes.TokenPlane] = "platform",
            [SecurityClaimTypes.PlatformTokenVersion] = platformTokenVersion,
            [TokenConstants.PlatformAdminTokenVersionClaim] = platformAdminTokenVersion,
            [SecurityClaimTypes.Scopes] = scopes,
            [SecurityClaimTypes.Scope] = string.Join(' ', scopes),
            [SecurityClaimTypes.Roles] = roles,
            [SecurityClaimTypes.Permissions] = permissions,
        };

        if (!string.IsNullOrWhiteSpace(env.EnvironmentId))
        {
            payload[TokenConstants.EnvironmentIdClaim] = env.EnvironmentId;
        }

        var headerJson = JsonSerializer.Serialize(header, new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
        var payloadJson = JsonSerializer.Serialize(payload, new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });

        var headerPart = Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson));
        var payloadPart = Base64Url.Encode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = headerPart + "." + payloadPart;

        var signature = Sign(signingInput, keys);
        return (signingInput + "." + signature, exp);
    }

    private static async Task<Results<JsonHttpResult<ApiResponse<BootstrapResult>>, JsonHttpResult<ApiResponse<object>>>> BootstrapAsync(
        HttpContext http,
        IConfiguration config,
        BootstrapRequest request,
        CancellationToken ct)
    {
        var db = http.RequestServices.GetRequiredService<SecurityDbContext>();
        var tenants = http.RequestServices.GetRequiredService<ITenantRepository>();
        var subjects = http.RequestServices.GetRequiredService<ISubjectRepository>();
        var localAccounts = http.RequestServices.GetRequiredService<ILocalAccountRepository>();
        var authzAdmin = http.RequestServices.GetRequiredService<IAuthorizationAdminStore>();

        if (request is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "request body is required"), statusCode: StatusCodes.Status400BadRequest);
        }

        if (!await HasValidBootstrapKeyAsync(http, config, TryGetBootstrapKeyFromHeader(http), ct))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Forbidden, "invalid bootstrap key"), statusCode: StatusCodes.Status401Unauthorized);
        }

        if (string.IsNullOrWhiteSpace(request.Username))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "username is required", SingleField("username", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "password is required", SingleField("password", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var tenantId = request.TenantId ?? Guid.NewGuid();
        if (tenantId == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "tenantId is invalid", SingleField("tenantId", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var ourSubject = request.OurSubject ?? Guid.NewGuid();
        if (ourSubject == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "ourSubject is invalid", SingleField("ourSubject", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var tenantName = string.IsNullOrWhiteSpace(request.TenantName) ? "default" : request.TenantName.Trim();
        var productKey = string.IsNullOrWhiteSpace(request.ProductKey) ? "security" : request.ProductKey.Trim();
        var permissionKey = string.IsNullOrWhiteSpace(request.PermissionKey) ? "security.manage" : request.PermissionKey.Trim();

        await db.Database.EnsureCreatedAsync(ct);

        // This endpoint is intended for empty/new databases only.
        if (await db.Tenants.AsNoTracking().AnyAsync(ct))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Conflict, "database already initialized"), statusCode: StatusCodes.Status409Conflict);
        }

        // Core tenant + default admin subject + local credential.
        _ = await tenants.CreateAsync(tenantId, tenantName, ct);
        _ = await subjects.CreateAsync(tenantId, ourSubject, ct);
        _ = await localAccounts.CreateAsync(tenantId, ourSubject, request.Username.Trim(), request.Password, ct);

        // Seed a minimal product + permission catalog + entitlement so the tenant admin surface can list/manage.
        var now = DateTimeOffset.UtcNow;

        db.Products.Add(new ProductEntity
        {
            ProductId = Guid.NewGuid(),
            ProductKey = productKey,
            DisplayName = "Security",
            Description = "Bootstrap seeded product",
            Status = (int)ProductStatus.Enabled,
            CreatedAt = now,
            UpdatedAt = now,
        });

        db.Permissions.Add(new PermissionEntity
        {
            PermId = Guid.NewGuid(),
            PermKey = permissionKey,
            ProductKey = productKey,
            Description = "Bootstrap seeded permission",
            CreatedAt = now,
            UpdatedAt = now,
        });

        db.TenantProducts.Add(new TenantProductEntity
        {
            TenantId = tenantId,
            ProductKey = productKey,
            Status = (int)TenantProductStatus.Enabled,
            StartAt = now,
            EndAt = null,
            PlanJson = null,
            CreatedAt = now,
            UpdatedAt = now,
        });

        await db.SaveChangesAsync(ct);

        // Ensure the default admin can access tenant admin APIs.
        _ = await authzAdmin.SetSubjectGrantsAsync(
            tenantId,
            ourSubject,
            new AuthorizationGrants(Roles: [], Scopes: ["security.admin"], Permissions: []),
            reason: "bootstrap",
            cancellationToken: ct);

        return TypedResults.Json(ApiResponse<BootstrapResult>.Ok(new BootstrapResult(
            TenantId: tenantId,
            OurSubject: ourSubject,
            Username: request.Username.Trim(),
            ProductKey: productKey,
            PermissionKey: permissionKey)));
    }

    private static async Task<long> GetCurrentPlatformTokenVersionAsync(HttpContext http, CancellationToken ct)
    {
        var store = http.RequestServices.GetRequiredService<IPlatformTokenVersionStore>();
        return await store.GetCurrentAsync(ct);
    }

    private static async Task<Results<JsonHttpResult<ApiResponse<PlatformBootstrapExchangeResult>>, JsonHttpResult<ApiResponse<object>>>> BootstrapPlatformTokenExchangeAsync(
        HttpContext http,
        IConfiguration config,
        IJwtKeyProvider keys,
        IOptionsMonitor<JwtOptions> jwtOptions,
        IOptionsMonitor<SecurityEnvironmentOptions> envOptions,
        IAuditEventWriter audit,
        PlatformBootstrapExchangeRequest request,
        CancellationToken ct)
    {
        _ = ct;

        if (request is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "request body is required"), statusCode: StatusCodes.Status400BadRequest);
        }

        var providedKey = request.BootstrapKey ?? TryGetBootstrapKeyFromHeader(http);
        if (!await HasValidBootstrapKeyAsync(http, config, providedKey, ct))
        {
            await audit.WriteAsync(new AuthEvent
            {
                Id = Guid.NewGuid(),
                OccurredAt = DateTimeOffset.UtcNow,
                TenantId = null,
                OurSubject = request.OurSubject,
                SessionId = null,
                Type = AuthEventType.SecurityDefense,
                Outcome = "failed",
                Code = "platform.bootstrap.exchange",
                ErrorCode = AuthErrorCodes.Forbidden,
                Detail = "invalid bootstrap key",
                CorrelationId = http.GetCorrelationId(),
                TraceId = http.GetTraceId(),
                Ip = http.Connection.RemoteIpAddress?.ToString(),
                UserAgent = http.Request.Headers.UserAgent.ToString(),
            }, ct);

            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Forbidden, "invalid bootstrap key"), statusCode: StatusCodes.Status401Unauthorized);
        }

        var ourSubject = request.OurSubject ?? Guid.NewGuid();
        if (ourSubject == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "ourSubject is invalid", SingleField("ourSubject", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var role = string.IsNullOrWhiteSpace(request.Role) ? PlatformRoles.SuperAdmin : request.Role.Trim();
        if (!string.Equals(role, PlatformRoles.SuperAdmin, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(role, PlatformRoles.OpsAdmin, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(role, PlatformRoles.ReadonlyAdmin, StringComparison.OrdinalIgnoreCase))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "role is invalid", SingleField("role", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var tv = await GetCurrentPlatformTokenVersionAsync(http, ct);

        var adminStore = http.RequestServices.GetService<IPlatformAdminStore>();
        if (adminStore is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InternalError, "platform admin store is not configured"), statusCode: StatusCodes.Status500InternalServerError);
        }

        // Ensure the platform admin record exists for this subject so the token can be validated.
        var existing = await adminStore.FindAsync(ourSubject, ct);
        var record = existing ?? await adminStore.CreateAsync(ourSubject, role, reason: "bootstrap", cancellationToken: ct);

        if (record.Status != PlatformAdminStatus.Active)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Forbidden, "platform admin is disabled"), statusCode: StatusCodes.Status403Forbidden);
        }

        // Keep store and requested role consistent.
        if (!string.Equals(record.Role, role, StringComparison.OrdinalIgnoreCase))
        {
            record = await adminStore.SetRoleAsync(ourSubject, role, reason: "bootstrap", cancellationToken: ct)
                ?? record;
        }

        var (token, exp) = CreatePlatformAccessToken(keys, jwtOptions.CurrentValue, envOptions.CurrentValue, ourSubject, role, record.TokenVersion, tv);

        await audit.WriteAsync(new AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = null,
            OurSubject = ourSubject,
            SessionId = null,
            Type = AuthEventType.TokenIssued,
            Outcome = "success",
            Code = "platform.bootstrap.exchange",
            Detail = request.Reason,
            MetaJson = JsonSerializer.Serialize(new { ourSubject, role }, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return TypedResults.Json(ApiResponse<PlatformBootstrapExchangeResult>.Ok(new PlatformBootstrapExchangeResult(
            OurSubject: ourSubject,
            PlatformAccessToken: token,
            ExpiresAt: exp,
            TokenType: "platform_access",
            Scope: "platform")));
    }

    private static async Task<Results<JsonHttpResult<ApiResponse<PlatformBootstrapTokenResult>>, JsonHttpResult<ApiResponse<object>>>> BootstrapPlatformTokenAsync(
        HttpContext http,
        IConfiguration config,
        PlatformBootstrapTokenRequest? request,
        IJwtKeyProvider keys,
        IOptionsMonitor<JwtOptions> jwtOptions,
        IOptionsMonitor<SecurityEnvironmentOptions> envOptions,
        CancellationToken ct)
    {
        if (!await HasValidBootstrapKeyAsync(http, config, TryGetBootstrapKeyFromHeader(http), ct))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Forbidden, "invalid bootstrap key"), statusCode: StatusCodes.Status401Unauthorized);
        }

        var ourSubject = request?.OurSubject ?? Guid.NewGuid();
        if (ourSubject == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "ourSubject is invalid", SingleField("ourSubject", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var role = string.IsNullOrWhiteSpace(request?.Role) ? PlatformRoles.SuperAdmin : request!.Role!.Trim();
        if (!string.Equals(role, PlatformRoles.SuperAdmin, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(role, PlatformRoles.OpsAdmin, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(role, PlatformRoles.ReadonlyAdmin, StringComparison.OrdinalIgnoreCase))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "role is invalid", SingleField("role", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var jwt = jwtOptions.CurrentValue;
        var env = envOptions.CurrentValue;

        var tv = await GetCurrentPlatformTokenVersionAsync(http, ct);

        var adminStore = http.RequestServices.GetService<IPlatformAdminStore>();
        if (adminStore is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InternalError, "platform admin store is not configured"), statusCode: StatusCodes.Status500InternalServerError);
        }

        var existing = await adminStore.FindAsync(ourSubject, ct);
        var record = existing ?? await adminStore.CreateAsync(ourSubject, role, reason: "bootstrap", cancellationToken: ct);
        if (record.Status != PlatformAdminStatus.Active)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Forbidden, "platform admin is disabled"), statusCode: StatusCodes.Status403Forbidden);
        }

        if (!string.Equals(record.Role, role, StringComparison.OrdinalIgnoreCase))
        {
            record = await adminStore.SetRoleAsync(ourSubject, role, reason: "bootstrap", cancellationToken: ct)
                ?? record;
        }

        var (token, expiresAt) = CreatePlatformAccessToken(keys, jwt, env, ourSubject, role, record.TokenVersion, tv);
        var result = new PlatformBootstrapTokenResult(OurSubject: ourSubject, AccessToken: token, ExpiresAt: expiresAt);

        return TypedResults.Json(ApiResponse<PlatformBootstrapTokenResult>.Ok(result));
    }
}
