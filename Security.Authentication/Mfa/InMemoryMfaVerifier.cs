namespace Birdsoft.Security.Authentication.Mfa;

using Birdsoft.Security.Abstractions.Mfa;

/// <summary>
/// Reference MFA verifier for development/testing.
/// Replace with a real provider-backed implementation (TOTP/SMS/WebAuthn/etc.).
/// </summary>
public sealed class InMemoryMfaVerifier : IMfaVerifier
{
    public Task<MfaVerifyResult> VerifyAsync(Guid tenantId, Guid ourSubject, string code, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = ourSubject;
        _ = cancellationToken;

        // Intentionally simple: accept a single static code.
        return Task.FromResult(code == "123456"
            ? new MfaVerifyResult(true)
            : new MfaVerifyResult(false, "mfa_failed"));
    }
}
