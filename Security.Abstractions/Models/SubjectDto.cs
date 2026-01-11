namespace Birdsoft.Security.Abstractions.Models;

public sealed record SubjectDto
{
    public required System.Guid TenantId { get; init; }
    public required System.Guid OurSubject { get; init; }
    public required UserStatus Status { get; init; }
    public required int TokenVersion { get; init; }
    public required System.DateTimeOffset CreatedAt { get; init; }
}
