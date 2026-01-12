namespace Birdsoft.Security.Authorization.Api.Observability.Logging;

using Birdsoft.Infrastructure.Logging.Abstractions;
using System.Globalization;

public sealed class AuthErrorLogFilePathProvider : ILogFilePathProvider
{
    private readonly string _rootDirectory;

    public AuthErrorLogFilePathProvider(string rootDirectory)
    {
        if (string.IsNullOrWhiteSpace(rootDirectory))
        {
            throw new ArgumentException("Root directory is required.", nameof(rootDirectory));
        }

        _rootDirectory = rootDirectory;
    }

    public string GetLogFilePath(DateOnly date)
    {
        // Must match Authentication service error file naming.
        var fileName = "auth-error-" + date.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".jsonl";
        return Path.Combine(_rootDirectory, fileName);
    }
}
