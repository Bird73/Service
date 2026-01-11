namespace Birdsoft.Security.Abstractions.Stores;

using Birdsoft.Security.Abstractions.Models;

public interface IAuthEventStore
{
    Task AppendAsync(AuthEvent ev, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuthEvent>> QueryAsync(AuthEventQuery query, CancellationToken cancellationToken = default);
}
