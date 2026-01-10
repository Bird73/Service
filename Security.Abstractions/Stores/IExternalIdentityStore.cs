namespace Birdsoft.Security.Abstractions.Stores;

using Birdsoft.Security.Abstractions.Identity;

public interface IExternalIdentityStore
{
    ValueTask<ExternalIdentityMapping?> FindMappingAsync(
        ExternalIdentityKey key,
        CancellationToken cancellationToken = default);

    ValueTask<ExternalIdentityMapping> CreateMappingAsync(
        ExternalIdentityMapping mapping,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 視需求提供 Upsert（例如後續支援 issuer 變更/修正）。
    /// 若不需要可由實作丟 NotSupportedException。
    /// </summary>
    ValueTask<ExternalIdentityMapping> UpsertMappingAsync(
        ExternalIdentityMapping mapping,
        CancellationToken cancellationToken = default);
}
