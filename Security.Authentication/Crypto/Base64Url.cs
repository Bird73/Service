namespace Birdsoft.Security.Authentication;

internal static class Base64Url
{
    public static string Encode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static byte[] Decode(string input)
    {
        var padded = input
            .Replace('-', '+')
            .Replace('_', '/');

        var padding = 4 - (padded.Length % 4);
        if (padding is > 0 and < 4)
        {
            padded = padded + new string('=', padding);
        }

        return Convert.FromBase64String(padded);
    }
}
