namespace Birdsoft.Security.Authentication.Persistence;

using Birdsoft.Security.Abstractions.Identity;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Stores;

public sealed class ExternalIdentityStoreFromRepository : IExternalIdentityStore
{
    private readonly IExternalIdentityRepository _repo;

    public ExternalIdentityStoreFromRepository(IExternalIdentityRepository repo)
    {
        _repo = repo;
    }

    public async ValueTask<ExternalIdentityMapping?> FindMappingAsync(ExternalIdentityKey key, CancellationToken cancellationToken = default)
    {
        var dto = await _repo.FindAsync(
            key.TenantId,
            key.Provider,
            key.Issuer,
            key.ProviderSubject,
            cancellationToken);

        return dto is null
            ? null
            : new ExternalIdentityMapping(
                dto.TenantId,
                dto.OurSubject,
                dto.Provider,
                dto.Issuer,
                dto.ProviderSub,
                CreatedAt: DateTimeOffset.UtcNow,
                Enabled: dto.Enabled,
                DisabledAt: dto.DisabledAt,
                DisabledReason: dto.DisabledReason);
    }

    public async ValueTask<ExternalIdentityMapping> CreateMappingAsync(ExternalIdentityMapping mapping, CancellationToken cancellationToken = default)
    {
        var dto = await _repo.CreateAsync(
            mapping.TenantId,
            mapping.OurSubject,
            mapping.Provider,
            mapping.Issuer,
            mapping.ProviderSubject,
            cancellationToken);

        return new ExternalIdentityMapping(
            dto.TenantId,
            dto.OurSubject,
            dto.Provider,
            dto.Issuer,
            dto.ProviderSub,
            CreatedAt: DateTimeOffset.UtcNow,
            Enabled: dto.Enabled,
            DisabledAt: dto.DisabledAt,
            DisabledReason: dto.DisabledReason);
    }

    public async ValueTask<ExternalIdentityMapping> UpsertMappingAsync(ExternalIdentityMapping mapping, CancellationToken cancellationToken = default)
    {
        var existing = await FindMappingAsync(
            new ExternalIdentityKey(mapping.TenantId, mapping.Provider, mapping.Issuer, mapping.ProviderSubject),
            cancellationToken);

        return existing ?? await CreateMappingAsync(mapping, cancellationToken);
    }

    public async ValueTask<bool> DisableMappingAsync(ExternalIdentityKey key, DateTimeOffset disabledAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        return await _repo.DisableAsync(key.TenantId, key.Provider, key.Issuer, key.ProviderSubject, disabledAt, reason, cancellationToken);
    }
}
