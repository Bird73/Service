namespace Birdsoft.Security.Authorization.Evaluation;

public sealed record AuthorizationRequest(
    Guid TenantId,
    Guid OurSubject,
    string Resource,
    string Action,
    IReadOnlyDictionary<string, object?>? Context = null);
