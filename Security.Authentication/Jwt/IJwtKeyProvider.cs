namespace Birdsoft.Security.Authentication.Jwt;

using System.Security.Cryptography;

public interface IJwtKeyProvider
{
    string Algorithm { get; }
    string Kid { get; }

    /// <summary>
    /// Returns a private RSA key for signing when using RS256.
    /// </summary>
    RSA? GetRsaPrivateKey();

    /// <summary>
    /// Returns a public RSA key for validation and JWKS output when using RS256.
    /// </summary>
    RSA? GetRsaPublicKey();

    /// <summary>
    /// Returns the symmetric key bytes for HMAC algorithms.
    /// </summary>
    byte[]? GetSymmetricKeyBytes();

    object GetJwksDocument();
}
