namespace Birdsoft.Security.Authentication;

using System.Security.Cryptography;

internal static class Pkce
{
    public static string CreateCodeVerifier(int bytes = 32)
    {
        var buffer = RandomNumberGenerator.GetBytes(bytes);
        return Base64Url.Encode(buffer);
    }
}
