namespace Birdsoft.Security.Authorization.Stores;

using Birdsoft.Security.Abstractions.Stores;
using System.Collections.Concurrent;

/// <summary>
/// In-memory authorization store for development/testing.
/// Provides both read-side (IAuthorizationDataStore) and admin governance (IAuthorizationAdminStore).
/// </summary>
public sealed class InMemoryAuthorizationStore : IAuthorizationDataStore, IAuthorizationAdminStore
{
    private sealed record Entry(AuthorizationGrants Grants, long GrantsVersion);

    private readonly ConcurrentDictionary<(Guid TenantId, Guid OurSubject), Entry> _grants = new();
    private readonly ConcurrentDictionary<Guid, long> _tenantVersions = new();

    public ValueTask<IReadOnlyList<string>> GetRolesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        return ValueTask.FromResult<IReadOnlyList<string>>(Get(tenantId, ourSubject).Grants.Roles);
    }

    public ValueTask<IReadOnlyList<string>> GetScopesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        return ValueTask.FromResult<IReadOnlyList<string>>(Get(tenantId, ourSubject).Grants.Scopes);
    }

    public ValueTask<IReadOnlyList<string>> GetPermissionsAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        return ValueTask.FromResult<IReadOnlyList<string>>(Get(tenantId, ourSubject).Grants.Permissions);
    }

    public ValueTask<(AuthorizationGrants Grants, long TenantModelVersion, long SubjectGrantsVersion)?> GetSubjectGrantsAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;

        if (!_grants.TryGetValue((tenantId, ourSubject), out var entry))
        {
            return ValueTask.FromResult<(AuthorizationGrants, long, long)?>(null);
        }

        var tenantVersion = _tenantVersions.TryGetValue(tenantId, out var v) ? v : 0;
        return ValueTask.FromResult<(AuthorizationGrants, long, long)?>((entry.Grants, tenantVersion, entry.GrantsVersion));
    }

    public ValueTask<AuthorizationChangeReceipt> SetSubjectGrantsAsync(Guid tenantId, Guid ourSubject, AuthorizationGrants grants, string? reason = null, CancellationToken cancellationToken = default)
    {
        _ = reason;
        _ = cancellationToken;

        var tenantVersion = _tenantVersions.AddOrUpdate(tenantId, 1, (_, old) => old + 1);
        var entry = _grants.AddOrUpdate(
            (tenantId, ourSubject),
            _ => new Entry(grants, GrantsVersion: 1),
            (_, old) => old with { Grants = grants, GrantsVersion = old.GrantsVersion + 1 });

        return ValueTask.FromResult(new AuthorizationChangeReceipt(
            TenantModelVersion: tenantVersion,
            SubjectGrantsVersion: entry.GrantsVersion,
            ChangedAt: DateTimeOffset.UtcNow));
    }

    private Entry Get(Guid tenantId, Guid ourSubject)
        => _grants.TryGetValue((tenantId, ourSubject), out var entry)
            ? entry
            : new Entry(new AuthorizationGrants([], [], []), GrantsVersion: 0);
}
