namespace Birdsoft.Security.Abstractions.Models;

public sealed record AuthEventQuery(
    Guid? TenantId = null,
    Guid? OurSubject = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int Skip = 0,
    int Take = 100);
