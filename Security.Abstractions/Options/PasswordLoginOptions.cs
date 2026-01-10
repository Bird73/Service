namespace Birdsoft.Security.Abstractions.Options;

public sealed class PasswordLoginOptions
{
    public const string SectionName = "Security:PasswordLogin";

    public bool Enabled { get; init; } = false;

    public IReadOnlyList<PasswordLoginUser> Users { get; init; } = [];
}

public sealed record PasswordLoginUser(
    string Username,
    string Password,
    Guid OurSubject);
