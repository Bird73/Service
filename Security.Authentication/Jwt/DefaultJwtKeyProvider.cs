namespace Birdsoft.Security.Authentication.Jwt;

using Birdsoft.Security.Abstractions.Options;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

public sealed class DefaultJwtKeyProvider : IJwtKeyProvider
{
    private sealed record KeyState(
        string Algorithm,
        string Kid,
        RSA? RsaPrivate,
        RSA? RsaPublic,
        byte[]? SymmetricKeyBytes,
        object Jwks);

    private readonly IOptionsMonitor<JwtOptions> _options;
    private readonly object _gate = new();
    private KeyState? _state;

    public DefaultJwtKeyProvider(IOptionsMonitor<JwtOptions> options)
    {
        _options = options;
    }

    public string Algorithm => Ensure().Algorithm;

    public string Kid => Ensure().Kid;

    public RSA? GetRsaPrivateKey() => Ensure().RsaPrivate;

    public RSA? GetRsaPublicKey() => Ensure().RsaPublic;

    public byte[]? GetSymmetricKeyBytes() => Ensure().SymmetricKeyBytes;

    public object GetJwksDocument() => Ensure().Jwks;

    private KeyState Ensure()
    {
        var snapshot = _state;
        if (snapshot is not null)
        {
            return snapshot;
        }

        lock (_gate)
        {
            if (_state is not null)
            {
                return _state;
            }

            var opts = _options.CurrentValue;
            var alg = string.IsNullOrWhiteSpace(opts.SigningAlgorithm) ? "RS256" : opts.SigningAlgorithm.Trim();

            if (alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                var rsaPrivate = CreateOrLoadRsaPrivate(opts.SigningKey);
                var rsaPublic = CreateRsaPublic(rsaPrivate);

                var (n, e) = ExportRsaJwkParameters(rsaPublic);
                var kid = !string.IsNullOrWhiteSpace(opts.Kid)
                    ? opts.Kid!
                    : ComputeKid(n, e);

                var jwk = new
                {
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    kid,
                    n,
                    e,
                };

                var jwks = new { keys = new[] { jwk } };
                _state = new KeyState("RS256", kid, rsaPrivate, rsaPublic, null, jwks);
                return _state;
            }

            // Default to HS256/HS512 style symmetric signing.
            // For security, we do NOT publish symmetric secrets in JWKS.
            var symKey = string.IsNullOrWhiteSpace(opts.SigningKey)
                ? null
                : Encoding.UTF8.GetBytes(opts.SigningKey);

            var symKid = !string.IsNullOrWhiteSpace(opts.Kid)
                ? opts.Kid!
                : "sym";

            _state = new KeyState(alg.ToUpperInvariant(), symKid, null, null, symKey, new { keys = Array.Empty<object>() });
            return _state;
        }
    }

    private static RSA CreateOrLoadRsaPrivate(string? signingKey)
    {
        var rsa = RSA.Create();

        if (string.IsNullOrWhiteSpace(signingKey))
        {
            rsa.KeySize = 2048;
            return rsa;
        }

        // PEM (recommended)
        if (signingKey.Contains("BEGIN", StringComparison.Ordinal))
        {
            rsa.ImportFromPem(signingKey);
            return rsa;
        }

        // Base64 PKCS#8 private key (optional)
        try
        {
            var pkcs8 = Convert.FromBase64String(signingKey);
            rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            return rsa;
        }
        catch
        {
            // Fall back to treating it as a literal string; generate an ephemeral key.
            rsa.KeySize = 2048;
            return rsa;
        }
    }

    private static RSA CreateRsaPublic(RSA rsaPrivate)
    {
        var rsaPublic = RSA.Create();
        rsaPublic.ImportParameters(rsaPrivate.ExportParameters(includePrivateParameters: false));
        return rsaPublic;
    }

    private static (string n, string e) ExportRsaJwkParameters(RSA rsaPublic)
    {
        var p = rsaPublic.ExportParameters(includePrivateParameters: false);
        if (p.Modulus is null || p.Exponent is null)
        {
            throw new InvalidOperationException("RSA public parameters missing.");
        }

        return (Base64Url.Encode(p.Modulus), Base64Url.Encode(p.Exponent));
    }

    private static string ComputeKid(string n, string e)
    {
        var input = Encoding.ASCII.GetBytes(n + "." + e);
        var hash = SHA256.HashData(input);
        var kid = Base64Url.Encode(hash);
        return kid.Length <= 16 ? kid : kid[..16];
    }
}
