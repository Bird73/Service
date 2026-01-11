namespace Birdsoft.Security.Authentication.Mfa;

using System.Collections.Concurrent;
using Birdsoft.Security.Abstractions.Mfa;

public sealed class InMemoryMfaChallengeStore : IMfaChallengeStore
{
    private readonly ConcurrentDictionary<Guid, MfaChallenge> _items = new();

    public Task<MfaChallenge> CreateAsync(Guid tenantId, Guid ourSubject, TimeSpan ttl, string? providerHint = null, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;

        var challenge = new MfaChallenge(
            ChallengeId: Guid.NewGuid(),
            TenantId: tenantId,
            OurSubject: ourSubject,
            ExpiresAt: DateTimeOffset.UtcNow.Add(ttl),
            ProviderHint: providerHint);

        _items[challenge.ChallengeId] = challenge;
        return Task.FromResult(challenge);
    }

    public Task<MfaChallenge?> FindAsync(Guid challengeId, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        return Task.FromResult(_items.TryGetValue(challengeId, out var v) ? v : null);
    }

    public Task<bool> ConsumeAsync(Guid challengeId, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        return Task.FromResult(_items.TryRemove(challengeId, out _));
    }
}
