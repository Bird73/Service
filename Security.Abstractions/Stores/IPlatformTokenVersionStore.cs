namespace Birdsoft.Security.Abstractions.Stores;

/// <summary>
/// Minimal platform token revocation mechanism.
///
/// Platform access tokens include a monotonic version claim.
/// When the version is bumped, all previously issued platform tokens are immediately invalid.
/// </summary>
public interface IPlatformTokenVersionStore
{
    ValueTask<long> GetCurrentAsync(CancellationToken cancellationToken = default);

    ValueTask<long> BumpAsync(string? reason = null, CancellationToken cancellationToken = default);
}
