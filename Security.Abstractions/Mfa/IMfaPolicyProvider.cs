namespace Birdsoft.Security.Abstractions.Mfa;

public interface IMfaPolicyProvider
{
    Task<MfaPolicy> GetPolicyAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default);
}
