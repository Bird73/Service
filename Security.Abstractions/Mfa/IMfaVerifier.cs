namespace Birdsoft.Security.Abstractions.Mfa;

public sealed record MfaVerifyResult(bool Succeeded, string? ErrorCode = null);

public interface IMfaVerifier
{
    Task<MfaVerifyResult> VerifyAsync(Guid tenantId, Guid ourSubject, string code, CancellationToken cancellationToken = default);
}
