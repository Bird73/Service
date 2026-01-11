namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class ExternalIdentityEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid OurSubject { get; set; }
    public string Provider { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string ProviderSub { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
}
