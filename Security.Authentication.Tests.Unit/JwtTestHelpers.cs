namespace Birdsoft.Security.Authentication.Tests.Unit;

using System.Text;
using System.Text.Json;

internal static class JwtTestHelpers
{
    public static JsonElement DecodeJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.True(parts.Length == 3);

        var json = Encoding.UTF8.GetString(DecodeBase64Url(parts[1]));
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    public static JsonElement DecodeJwtHeader(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.True(parts.Length == 3);

        var json = Encoding.UTF8.GetString(DecodeBase64Url(parts[0]));
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    public static byte[] DecodeBase64Url(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        var padding = 4 - (padded.Length % 4);
        if (padding is > 0 and < 4)
        {
            padded += new string('=', padding);
        }

        return Convert.FromBase64String(padded);
    }
}
