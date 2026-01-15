namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class SubjectRoleEntity
{
    public Guid TenantId { get; set; }
    public Guid OurSubject { get; set; }
    public Guid RoleId { get; set; }

    public DateTimeOffset AssignedAt { get; set; }
}
