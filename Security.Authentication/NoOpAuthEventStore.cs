namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Stores;

public sealed class NoOpAuthEventStore : IAuthEventStore
{
    public Task AppendAsync(AuthEvent ev, CancellationToken cancellationToken = default)
    {
        _ = ev;
        _ = cancellationToken;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuthEvent>> QueryAsync(AuthEventQuery query, CancellationToken cancellationToken = default)
    {
        _ = query;
        _ = cancellationToken;
        return Task.FromResult<IReadOnlyList<AuthEvent>>([]);
    }
}
