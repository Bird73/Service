namespace Birdsoft.Security.Abstractions.Audit;

using Birdsoft.Security.Abstractions.Models;

public interface IAuditEventWriter
{
    Task WriteAsync(AuthEvent ev, CancellationToken cancellationToken = default);
}
