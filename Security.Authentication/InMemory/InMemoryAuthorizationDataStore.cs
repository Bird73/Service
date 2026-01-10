namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions.Stores;

public sealed class InMemoryAuthorizationDataStore : IAuthorizationDataStore
{
    public ValueTask<IReadOnlyList<string>> GetRolesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = ourSubject;
        _ = cancellationToken;
        return ValueTask.FromResult<IReadOnlyList<string>>([]);
    }

    public ValueTask<IReadOnlyList<string>> GetScopesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = ourSubject;
        _ = cancellationToken;
        return ValueTask.FromResult<IReadOnlyList<string>>([]);
    }
}
