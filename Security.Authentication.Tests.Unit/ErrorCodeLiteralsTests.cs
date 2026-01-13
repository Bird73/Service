using System.Text.RegularExpressions;

namespace Birdsoft.Security.Authentication.Tests.Unit;

public sealed class ErrorCodeLiteralsTests
{
    [Fact]
    public void ApiResponseFail_error_code_must_not_be_string_literal()
    {
        var repoRoot = FindRepoRoot();

        var targets = new[]
        {
            Path.Combine(repoRoot, "Service", "Security.Authentication"),
            Path.Combine(repoRoot, "Service", "Security.Authorization.Api"),
        };

        // Matches: ApiResponse<T>.Fail(<first-arg contains a string literal before the first ',' or ')'>)
        // This catches both single-line and multi-line invocations, including patterns like:
        // Fail(verify.ErrorCode ?? "mfa_failed", ...)
        var regex = new Regex(
            "ApiResponse\\s*(?:<[^>]+>)?\\s*\\.\\s*Fail\\s*\\(\\s*[^,\\)]*\"",
            RegexOptions.Compiled | RegexOptions.Singleline);

        var offenders = new List<string>();

        foreach (var target in targets)
        {
            if (!Directory.Exists(target))
            {
                continue;
            }

            foreach (var filePath in EnumerateCsFiles(target))
            {
                var content = File.ReadAllText(filePath);
                foreach (Match match in regex.Matches(content))
                {
                    var line = 1 + CountNewLines(content, match.Index);
                    offenders.Add($"{ToRepoRelative(repoRoot, filePath)}:{line}");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Hard-coded ApiResponse.Fail(errorCode) string literal(s) found. Use AuthErrorCodes constants instead:\n" +
            string.Join("\n", offenders));
    }

    private static IEnumerable<string> EnumerateCsFiles(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var current = stack.Pop();

            foreach (var dir in Directory.EnumerateDirectories(current))
            {
                var name = Path.GetFileName(dir);
                if (string.Equals(name, "bin", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(name, "obj", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                stack.Push(dir);
            }

            foreach (var file in Directory.EnumerateFiles(current, "*.cs"))
            {
                yield return file;
            }
        }
    }

    private static int CountNewLines(string content, int upToIndex)
    {
        var count = 0;
        for (var i = 0; i < upToIndex && i < content.Length; i++)
        {
            if (content[i] == '\n')
            {
                count++;
            }
        }
        return count;
    }

    private static string ToRepoRelative(string repoRoot, string filePath)
    {
        var rel = Path.GetRelativePath(repoRoot, filePath);
        return rel.Replace('\\', '/');
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "Service")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root (expected to find a 'Service' directory).");
    }
}
