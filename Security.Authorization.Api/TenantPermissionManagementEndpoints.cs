namespace Birdsoft.Security.Authorization.Api;

using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;

internal static class TenantPermissionManagementEndpoints
{
    public static RouteGroupBuilder MapTenantPermissionManagement(this RouteGroupBuilder tenant)
    {
        tenant.MapGet("/permissions", GetTenantPermissionsAsync);
        tenant.MapPost("/users/{userId:guid}/permissions", AddUserPermissionAsync);
        tenant.MapDelete("/users/{userId:guid}/permissions/{permissionKey}", RemoveUserPermissionAsync);
        return tenant;
    }

    private static IReadOnlyDictionary<string, string[]> SingleField(string field, string message)
        => new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase) { [field] = [message] };

    private static Guid? TryGetTenantIdFromToken(HttpContext http)
    {
        var claim = http.User?.FindFirst(SecurityClaimTypes.TenantId)?.Value;
        if (!string.IsNullOrWhiteSpace(claim) && Guid.TryParse(claim, out var tenantId))
        {
            return tenantId;
        }

        return null;
    }

    private static async Task<(bool Exists, IReadOnlyList<string> Roles, IReadOnlyList<string> Scopes, IReadOnlyList<string> DirectPermissions)> LoadRawSubjectGrantsAsync(
        SecurityDbContext db,
        Guid tenantId,
        Guid ourSubject,
        CancellationToken ct)
    {
        var subjectExists = await db.Subjects.AsNoTracking()
            .AnyAsync(x => x.TenantId == tenantId && x.OurSubject == ourSubject, ct);

        if (!subjectExists)
        {
            return (false, [], [], []);
        }

        var roles = await (
            from sr in db.SubjectRoles.AsNoTracking()
            join r in db.Roles.AsNoTracking() on new { sr.TenantId, sr.RoleId } equals new { r.TenantId, r.RoleId }
            where sr.TenantId == tenantId && sr.OurSubject == ourSubject
            select r.RoleName)
            .Distinct()
            .ToListAsync(ct);

        var scopes = await db.SubjectScopes.AsNoTracking()
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject)
            .Select(x => x.ScopeKey)
            .Distinct()
            .ToListAsync(ct);

        var directPermissions = await (
            from sp in db.SubjectPermissions.AsNoTracking()
            join p in db.Permissions.AsNoTracking() on sp.PermId equals p.PermId
            where sp.TenantId == tenantId && sp.OurSubject == ourSubject
            select p.PermKey)
            .Distinct()
            .ToListAsync(ct);

        return (true, roles, scopes, directPermissions);
    }

    internal sealed record TenantPermissionDto(string PermissionKey, string ProductKey, string? Description);
    internal sealed record TenantSetUserPermissionRequest(string PermissionKey, string? Reason);

    internal static async Task<Results<JsonHttpResult<ApiResponse<IReadOnlyList<TenantPermissionDto>>>, JsonHttpResult<ApiResponse<object>>>> GetTenantPermissionsAsync(
        HttpContext http,
        SecurityDbContext db,
        ITenantEntitlementStore entitlements,
        string? productKey,
        DateTimeOffset? now,
        CancellationToken ct)
    {
        var tenantId = TryGetTenantIdFromToken(http);
        if (tenantId is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "tenant_id claim is required"), statusCode: StatusCodes.Status400BadRequest);
        }

        var clock = now ?? DateTimeOffset.UtcNow;

        if (!string.IsNullOrWhiteSpace(productKey))
        {
            var enabled = await entitlements.IsProductEnabledAsync(tenantId.Value, productKey.Trim(), clock, ct);
            if (!enabled)
            {
                return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.ProductNotEnabled, "product is not enabled for tenant"), statusCode: StatusCodes.Status403Forbidden);
            }

            var items = await db.Permissions.AsNoTracking()
                .Where(p => p.ProductKey != null && p.ProductKey == productKey.Trim())
                .OrderBy(p => p.PermKey)
                .Select(p => new TenantPermissionDto(p.PermKey, p.ProductKey!, p.Description))
                .ToListAsync(ct);

            return TypedResults.Json(ApiResponse<IReadOnlyList<TenantPermissionDto>>.Ok(items));
        }

        // List permissions only for currently-enabled products.
        List<string> enabledProductKeys;
        if (db.Database.IsSqlite())
        {
            enabledProductKeys = await (
                from tp in db.TenantProducts.AsNoTracking()
                join p in db.Products.AsNoTracking() on tp.ProductKey equals p.ProductKey
                where tp.TenantId == tenantId.Value
                    && tp.Status == (int)TenantProductStatus.Enabled
                    && p.Status == (int)ProductStatus.Enabled
                select tp.ProductKey)
                .Distinct()
                .ToListAsync(ct);

            enabledProductKeys = enabledProductKeys
                .Distinct(StringComparer.Ordinal)
                .ToList();

            // Apply time-window filtering in-memory for SQLite.
            var timeWindows = await db.TenantProducts.AsNoTracking()
                .Where(tp => tp.TenantId == tenantId.Value
                    && tp.Status == (int)TenantProductStatus.Enabled
                    && enabledProductKeys.Contains(tp.ProductKey))
                .Select(tp => new { tp.ProductKey, tp.StartAt, tp.EndAt })
                .ToListAsync(ct);

            var active = timeWindows
                .Where(x => x.StartAt <= clock && (x.EndAt is null || x.EndAt > clock))
                .Select(x => x.ProductKey)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            enabledProductKeys = active;
        }
        else
        {
            enabledProductKeys = await (
                from tp in db.TenantProducts.AsNoTracking()
                join p in db.Products.AsNoTracking() on tp.ProductKey equals p.ProductKey
                where tp.TenantId == tenantId.Value
                    && tp.Status == (int)TenantProductStatus.Enabled
                    && p.Status == (int)ProductStatus.Enabled
                    && tp.StartAt <= clock
                    && (tp.EndAt == null || tp.EndAt > clock)
                select tp.ProductKey)
                .Distinct()
                .ToListAsync(ct);
        }

        if (enabledProductKeys.Count == 0)
        {
            return TypedResults.Json(ApiResponse<IReadOnlyList<TenantPermissionDto>>.Ok([]));
        }

        var results = await db.Permissions.AsNoTracking()
            .Where(p => p.ProductKey != null && enabledProductKeys.Contains(p.ProductKey))
            .OrderBy(p => p.ProductKey)
            .ThenBy(p => p.PermKey)
            .Select(p => new TenantPermissionDto(p.PermKey, p.ProductKey!, p.Description))
            .ToListAsync(ct);

        return TypedResults.Json(ApiResponse<IReadOnlyList<TenantPermissionDto>>.Ok(results));
    }

    internal static async Task<Results<JsonHttpResult<ApiResponse<AuthorizationChangeReceipt>>, JsonHttpResult<ApiResponse<object>>>> AddUserPermissionAsync(
        HttpContext http,
        SecurityDbContext db,
        Guid userId,
        TenantSetUserPermissionRequest request,
        IPermissionCatalogStore catalog,
        ITenantEntitlementStore entitlements,
        IAuthorizationAdminStore admin,
        DateTimeOffset? now,
        CancellationToken ct)
    {
        var tenantId = TryGetTenantIdFromToken(http);
        if (tenantId is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "tenant_id claim is required"), statusCode: StatusCodes.Status400BadRequest);
        }

        if (userId == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "userId is required", SingleField("userId", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        if (string.IsNullOrWhiteSpace(request.PermissionKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "permissionKey is required", SingleField("permissionKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var clock = now ?? DateTimeOffset.UtcNow;
        var permissionKey = request.PermissionKey.Trim();

        var productKey = await catalog.GetProductKeyForPermissionAsync(permissionKey, ct);
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "permission not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var enabled = await entitlements.IsProductEnabledAsync(tenantId.Value, productKey, clock, ct);
        if (!enabled)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.ProductNotEnabled, "product is not enabled for tenant"), statusCode: StatusCodes.Status403Forbidden);
        }

        var (exists, roles, scopes, directPerms) = await LoadRawSubjectGrantsAsync(db, tenantId.Value, userId, ct);
        if (!exists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "user not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var updatedPerms = directPerms
            .Append(permissionKey)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToList();

        var receipt = await admin.SetSubjectGrantsAsync(
            tenantId.Value,
            userId,
            new AuthorizationGrants(roles, scopes, updatedPerms),
            reason: string.IsNullOrWhiteSpace(request.Reason) ? "tenant_permissions_api" : $"tenant_permissions_api: {request.Reason}",
            cancellationToken: ct);

        return TypedResults.Json(ApiResponse<AuthorizationChangeReceipt>.Ok(receipt));
    }

    internal static async Task<Results<JsonHttpResult<ApiResponse<AuthorizationChangeReceipt>>, JsonHttpResult<ApiResponse<object>>>> RemoveUserPermissionAsync(
        HttpContext http,
        SecurityDbContext db,
        Guid userId,
        string permissionKey,
        IPermissionCatalogStore catalog,
        ITenantEntitlementStore entitlements,
        IAuthorizationAdminStore admin,
        DateTimeOffset? now,
        CancellationToken ct)
    {
        var tenantId = TryGetTenantIdFromToken(http);
        if (tenantId is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "tenant_id claim is required"), statusCode: StatusCodes.Status400BadRequest);
        }

        if (userId == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "userId is required", SingleField("userId", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        if (string.IsNullOrWhiteSpace(permissionKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "permissionKey is required", SingleField("permissionKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var clock = now ?? DateTimeOffset.UtcNow;
        var normalizedPermissionKey = permissionKey.Trim();

        var productKey = await catalog.GetProductKeyForPermissionAsync(normalizedPermissionKey, ct);
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "permission not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var enabled = await entitlements.IsProductEnabledAsync(tenantId.Value, productKey, clock, ct);
        if (!enabled)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.ProductNotEnabled, "product is not enabled for tenant"), statusCode: StatusCodes.Status403Forbidden);
        }

        var (exists, roles, scopes, directPerms) = await LoadRawSubjectGrantsAsync(db, tenantId.Value, userId, ct);
        if (!exists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "user not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var updatedPerms = directPerms
            .Where(x => !string.Equals(x, normalizedPermissionKey, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToList();

        var receipt = await admin.SetSubjectGrantsAsync(
            tenantId.Value,
            userId,
            new AuthorizationGrants(roles, scopes, updatedPerms),
            reason: "tenant_permissions_api: remove",
            cancellationToken: ct);

        return TypedResults.Json(ApiResponse<AuthorizationChangeReceipt>.Ok(receipt));
    }
}
