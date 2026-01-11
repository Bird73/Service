namespace Birdsoft.Security.Abstractions.Stores;

public sealed record AuthorizationGrants(
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> Permissions);

public sealed record AuthorizationChangeReceipt(
    long TenantModelVersion,
    long SubjectGrantsVersion,
    DateTimeOffset ChangedAt);

/// <summary>
/// Governance/admin surface for authorization model changes.
/// Used by management APIs to update grants and trigger token/session invalidation.
/// </summary>
public interface IAuthorizationAdminStore
{
    ValueTask<(AuthorizationGrants Grants, long TenantModelVersion, long SubjectGrantsVersion)?> GetSubjectGrantsAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);

    ValueTask<AuthorizationChangeReceipt> SetSubjectGrantsAsync(
        Guid tenantId,
        Guid ourSubject,
        AuthorizationGrants grants,
        string? reason = null,
        CancellationToken cancellationToken = default);
}
