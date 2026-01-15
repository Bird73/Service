namespace Birdsoft.Security.Authentication.Bootstrap;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

internal static class BootstrapEndpoints
{
    private const string BootstrapKeyHeaderName = "X-Bootstrap-Key";

    public static RouteGroupBuilder MapBootstrapEndpoints(this RouteGroupBuilder api)
    {
        api.MapPost("/bootstrap", BootstrapAsync);
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

    private static IReadOnlyDictionary<string, string[]> SingleField(string field, string message)
        => new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase) { [field] = [message] };

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

        var expectedKey = config["Bootstrap:Key"];
        if (!string.IsNullOrWhiteSpace(expectedKey))
        {
            var providedKey = http.Request.Headers[BootstrapKeyHeaderName].ToString();
            if (!string.Equals(expectedKey, providedKey, StringComparison.Ordinal))
            {
                return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Forbidden, "invalid bootstrap key"), statusCode: StatusCodes.Status403Forbidden);
            }
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
}
