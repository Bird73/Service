namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class TokenSessionEntity
{
    public Guid TenantId { get; set; }
    public Guid SessionId { get; set; }

    public Guid OurSubject { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? TerminatedAt { get; set; }
    public string? TerminationReason { get; set; }

    public string? ClientId { get; set; }
    public string? DeviceId { get; set; }
    public string? Ip { get; set; }
    public string? UserAgent { get; set; }
}
