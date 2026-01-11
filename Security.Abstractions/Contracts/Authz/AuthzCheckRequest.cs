namespace Birdsoft.Security.Abstractions.Contracts.Authz;

public sealed record AuthzCheckRequest(
    Guid OurSubject,
    string Resource,
    string Action,
    IReadOnlyDictionary<string, object?>? Context = null);
