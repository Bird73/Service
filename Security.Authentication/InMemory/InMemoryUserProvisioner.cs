namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions.Identity;
using Birdsoft.Security.Abstractions.Services;

public sealed class InMemoryUserProvisioner : IUserProvisioner
{
    public Task<Guid> ProvisionAsync(
        Guid tenantId,
        ExternalIdentityKey externalIdentity,
        Birdsoft.Security.Abstractions.OidcUserInfo? userInfo = null,
        CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = externalIdentity;
        _ = userInfo;
        _ = cancellationToken;

        // Stub：用 new Guid 當作 our_subject。
        return Task.FromResult(Guid.NewGuid());
    }
}
