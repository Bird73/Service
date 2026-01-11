namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions.Identity;
using Birdsoft.Security.Abstractions.Stores;
using System.Collections.Concurrent;

public sealed class InMemoryExternalIdentityStore : IExternalIdentityStore
{
    private readonly ConcurrentDictionary<ExternalIdentityKey, ExternalIdentityMapping> _mappings = new();

    public ValueTask<ExternalIdentityMapping?> FindMappingAsync(ExternalIdentityKey key, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        return ValueTask.FromResult(_mappings.TryGetValue(key, out var mapping) ? mapping : null);
    }

    public ValueTask<ExternalIdentityMapping> CreateMappingAsync(ExternalIdentityMapping mapping, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var key = new ExternalIdentityKey(mapping.TenantId, mapping.Provider, mapping.Issuer, mapping.ProviderSubject);
        if (!_mappings.TryAdd(key, mapping))
        {
            throw new InvalidOperationException("Mapping already exists.");
        }

        return ValueTask.FromResult(mapping);
    }

    public ValueTask<ExternalIdentityMapping> UpsertMappingAsync(ExternalIdentityMapping mapping, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var key = new ExternalIdentityKey(mapping.TenantId, mapping.Provider, mapping.Issuer, mapping.ProviderSubject);
        _mappings[key] = mapping;
        return ValueTask.FromResult(mapping);
    }

    public ValueTask<bool> DisableMappingAsync(ExternalIdentityKey key, DateTimeOffset disabledAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (!_mappings.TryGetValue(key, out var mapping))
        {
            return ValueTask.FromResult(false);
        }

        if (!mapping.Enabled)
        {
            return ValueTask.FromResult(true);
        }

        _mappings[key] = mapping with { Enabled = false, DisabledAt = disabledAt, DisabledReason = reason };
        return ValueTask.FromResult(true);
    }
}
