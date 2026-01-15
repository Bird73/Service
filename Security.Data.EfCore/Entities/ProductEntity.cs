namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class ProductEntity
{
    public Guid ProductId { get; set; }

    public string ProductKey { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? Description { get; set; }

    public int Status { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
