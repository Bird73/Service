namespace Birdsoft.Security.Authentication;

using System.Security.Cryptography;

internal static class Nonce
{
    public static string Create(int bytes = 16)
    {
        var buffer = RandomNumberGenerator.GetBytes(bytes);
        return Base64Url.Encode(buffer);
    }
}
