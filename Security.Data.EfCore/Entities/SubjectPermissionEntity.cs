namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class SubjectPermissionEntity
{
    public Guid TenantId { get; set; }
    public Guid OurSubject { get; set; }
    public Guid PermId { get; set; }

    public DateTimeOffset AssignedAt { get; set; }
}
