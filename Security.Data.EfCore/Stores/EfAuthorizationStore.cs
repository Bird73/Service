namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfAuthorizationStore : IAuthorizationDataStore, IAuthorizationAdminStore
{
    private readonly SecurityDbContext _db;

    public EfAuthorizationStore(SecurityDbContext db) => _db = db;

    public async ValueTask<IReadOnlyList<string>> GetRolesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        var roles = await (
                from sr in _db.SubjectRoles.AsNoTracking()
                join r in _db.Roles.AsNoTracking() on new { sr.TenantId, sr.RoleId } equals new { r.TenantId, r.RoleId }
                where sr.TenantId == tenantId && sr.OurSubject == ourSubject
                select r.RoleName)
            .Distinct()
            .ToListAsync(cancellationToken);

        return roles;
    }

    public async ValueTask<IReadOnlyList<string>> GetScopesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        var scopes = await _db.SubjectScopes.AsNoTracking()
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject)
            .Select(x => x.ScopeKey)
            .Distinct()
            .ToListAsync(cancellationToken);

        return scopes;
    }

    public async ValueTask<IReadOnlyList<string>> GetPermissionsAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        var fromRoles =
            from sr in _db.SubjectRoles.AsNoTracking()
            join rp in _db.RolePermissions.AsNoTracking() on new { sr.TenantId, sr.RoleId } equals new { rp.TenantId, rp.RoleId }
            join p in _db.Permissions.AsNoTracking() on rp.PermId equals p.PermId
            where sr.TenantId == tenantId && sr.OurSubject == ourSubject
            select p.PermKey;

        var direct =
            from sp in _db.SubjectPermissions.AsNoTracking()
            join p in _db.Permissions.AsNoTracking() on sp.PermId equals p.PermId
            where sp.TenantId == tenantId && sp.OurSubject == ourSubject
            select p.PermKey;

        var perms = await fromRoles
            .Union(direct)
            .Distinct()
            .ToListAsync(cancellationToken);

        return perms;
    }

    public async ValueTask<(AuthorizationGrants Grants, long TenantModelVersion, long SubjectGrantsVersion)?> GetSubjectGrantsAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default)
    {
        // If subject doesn't exist, treat as missing.
        var subject = await _db.Subjects.AsNoTracking()
            .FirstOrDefaultAsync(x => x.TenantId == tenantId && x.OurSubject == ourSubject, cancellationToken);

        if (subject is null)
        {
            return null;
        }

        var tenantVer = await _db.AuthzTenantVersions.AsNoTracking()
            .Where(x => x.TenantId == tenantId)
            .Select(x => x.ModelVersion)
            .FirstOrDefaultAsync(cancellationToken);

        var roles = await GetRolesAsync(tenantId, ourSubject, cancellationToken);
        var scopes = await GetScopesAsync(tenantId, ourSubject, cancellationToken);

        // Admin surface: return direct (assigned) permissions only.
        // Effective permissions (role-derived + direct) are available via GetPermissionsAsync.
        var directPerms = await (
                from sp in _db.SubjectPermissions.AsNoTracking()
                join p in _db.Permissions.AsNoTracking() on sp.PermId equals p.PermId
                where sp.TenantId == tenantId && sp.OurSubject == ourSubject
                select p.PermKey)
            .Distinct()
            .ToListAsync(cancellationToken);

        return (new AuthorizationGrants(roles, scopes, directPerms), tenantVer, subject.TokenVersion);
    }

    public async ValueTask<AuthorizationChangeReceipt> SetSubjectGrantsAsync(
        Guid tenantId,
        Guid ourSubject,
        AuthorizationGrants grants,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        _ = reason;

        var now = DateTimeOffset.UtcNow;

        await using var tx = await _db.Database.BeginTransactionAsync(cancellationToken);

        // Ensure tenant authz version row exists.
        var tenantVer = await _db.AuthzTenantVersions
            .FirstOrDefaultAsync(x => x.TenantId == tenantId, cancellationToken);

        if (tenantVer is null)
        {
            tenantVer = new AuthzTenantVersionEntity { TenantId = tenantId, ModelVersion = 0, UpdatedAt = now };
            _db.AuthzTenantVersions.Add(tenantVer);
        }

        tenantVer.ModelVersion += 1;
        tenantVer.UpdatedAt = now;

        // Clear existing grants
        await _db.SubjectRoles.Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject).ExecuteDeleteAsync(cancellationToken);
        await _db.SubjectPermissions.Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject).ExecuteDeleteAsync(cancellationToken);
        await _db.SubjectScopes.Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject).ExecuteDeleteAsync(cancellationToken);

        // Roles: role names must exist; ignore unknown role names.
        if (grants.Roles.Count > 0)
        {
            var roleMap = await _db.Roles.AsNoTracking()
                .Where(x => x.TenantId == tenantId && grants.Roles.Contains(x.RoleName))
                .Select(x => new { x.RoleId, x.RoleName })
                .ToListAsync(cancellationToken);

            foreach (var r in roleMap)
            {
                _db.SubjectRoles.Add(new SubjectRoleEntity
                {
                    TenantId = tenantId,
                    OurSubject = ourSubject,
                    RoleId = r.RoleId,
                    AssignedAt = now,
                });
            }
        }

        // Direct permissions: perm keys must exist; ignore unknown perm keys.
        if (grants.Permissions.Count > 0)
        {
            var permMap = await _db.Permissions.AsNoTracking()
                .Where(x => grants.Permissions.Contains(x.PermKey))
                .Select(x => new { x.PermId, x.PermKey })
                .ToListAsync(cancellationToken);

            foreach (var p in permMap)
            {
                _db.SubjectPermissions.Add(new SubjectPermissionEntity
                {
                    TenantId = tenantId,
                    OurSubject = ourSubject,
                    PermId = p.PermId,
                    AssignedAt = now,
                });
            }
        }

        // Scopes: stored as literal keys (trim + de-dupe).
        var normalizedScopes = grants.Scopes
            .Select(s => s?.Trim())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s!)
            .Distinct(StringComparer.Ordinal);

        foreach (var scope in normalizedScopes)
        {
            _db.SubjectScopes.Add(new SubjectScopeEntity
            {
                TenantId = tenantId,
                OurSubject = ourSubject,
                ScopeKey = scope,
                AssignedAt = now,
            });
        }

        // Bump subject token version for immediate invalidation.
        var updated = await _db.Subjects
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.TokenVersion, x => x.TokenVersion + 1)
                .SetProperty(x => x.UpdatedAt, now), cancellationToken);

        if (updated == 0)
        {
            // Subject missing: do not create implicitly.
            throw new InvalidOperationException("Subject not found.");
        }

        await _db.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);

        var newSubjectVersion = await _db.Subjects.AsNoTracking()
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject)
            .Select(x => x.TokenVersion)
            .SingleAsync(cancellationToken);

        return new AuthorizationChangeReceipt(
            TenantModelVersion: tenantVer.ModelVersion,
            SubjectGrantsVersion: newSubjectVersion,
            ChangedAt: now);
    }
}
