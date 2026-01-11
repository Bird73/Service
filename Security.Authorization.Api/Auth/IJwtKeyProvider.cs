namespace Birdsoft.Security.Authorization.Api.Auth;

using System.Security.Cryptography;

public interface IJwtKeyProvider
{
    string Algorithm { get; }
    string Kid { get; }

    RSA? GetRsaPublicKey();

    byte[]? GetSymmetricKeyBytes();
}
