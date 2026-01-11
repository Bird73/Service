namespace Birdsoft.Security.Authorization.Api.Auth;

using Birdsoft.Security.Abstractions.Options;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

public sealed class DefaultJwtKeyProvider : IJwtKeyProvider
{
    private sealed record KeyState(
        string Algorithm,
        string Kid,
        RSA? RsaPublic,
        byte[]? SymmetricKeyBytes);

    private readonly IOptionsMonitor<JwtOptions> _options;
    private readonly object _gate = new();
    private KeyState? _state;

    public DefaultJwtKeyProvider(IOptionsMonitor<JwtOptions> options)
    {
        _options = options;
    }

    public string Algorithm => Ensure().Algorithm;

    public string Kid => Ensure().Kid;

    public RSA? GetRsaPublicKey() => Ensure().RsaPublic;

    public byte[]? GetSymmetricKeyBytes() => Ensure().SymmetricKeyBytes;

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
                // For validation we only need the public key. If a PEM/base64 private key is supplied,
                // we can derive its public part; otherwise we generate an ephemeral key (dev-only convenience).
                var rsaPrivate = CreateOrLoadRsaPrivate(opts.SigningKey);
                var rsaPublic = RSA.Create();
                rsaPublic.ImportParameters(rsaPrivate.ExportParameters(includePrivateParameters: false));

                var kid = !string.IsNullOrWhiteSpace(opts.Kid)
                    ? opts.Kid!
                    : "rsa";

                _state = new KeyState("RS256", kid, rsaPublic, null);
                return _state;
            }

            var symKey = string.IsNullOrWhiteSpace(opts.SigningKey)
                ? null
                : Encoding.UTF8.GetBytes(opts.SigningKey);

            var symKid = !string.IsNullOrWhiteSpace(opts.Kid)
                ? opts.Kid!
                : "sym";

            _state = new KeyState(alg.ToUpperInvariant(), symKid, null, symKey);
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

        if (signingKey.Contains("BEGIN", StringComparison.Ordinal))
        {
            rsa.ImportFromPem(signingKey);
            return rsa;
        }

        try
        {
            var pkcs8 = Convert.FromBase64String(signingKey);
            rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            return rsa;
        }
        catch
        {
            rsa.KeySize = 2048;
            return rsa;
        }
    }
}
