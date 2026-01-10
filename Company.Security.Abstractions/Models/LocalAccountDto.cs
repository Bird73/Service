namespace Company.Security.Abstractions.Models;

public sealed record LocalAccountDto
{
    public required System.Guid TenantId { get; init; }
    public required System.Guid OurSubject { get; init; }
    public required string UsernameOrEmail { get; init; }
    public required string PasswordHash { get; init; }
}
