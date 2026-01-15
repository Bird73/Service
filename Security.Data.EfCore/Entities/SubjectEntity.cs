namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class SubjectEntity
{
    public Guid TenantId { get; set; }
    public Guid OurSubject { get; set; }
    public string? DisplayName { get; set; }
    public int Status { get; set; }
    public int TokenVersion { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
