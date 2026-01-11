namespace Birdsoft.Security.Abstractions.Audit;

using System.Text.Json;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Observability.Metrics;
using Birdsoft.Security.Abstractions.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

public sealed class ResilientAuditEventWriter : IAuditEventWriter
{
    private readonly IAuthEventStore _store;
    private readonly IOptionsMonitor<AuditReliabilityOptions> _options;
    private readonly ILogger<ResilientAuditEventWriter> _logger;

    public ResilientAuditEventWriter(
        IAuthEventStore store,
        IOptionsMonitor<AuditReliabilityOptions> options,
        ILogger<ResilientAuditEventWriter> logger)
    {
        _store = store;
        _options = options;
        _logger = logger;
    }

    public async Task WriteAsync(AuthEvent ev, CancellationToken cancellationToken = default)
    {
        var opts = _options.CurrentValue;
        Exception? last = null;

        for (var attempt = 0; attempt <= Math.Max(0, opts.MaxRetries); attempt++)
        {
            try
            {
                await _store.AppendAsync(ev, cancellationToken);
                return;
            }
            catch (Exception ex)
            {
                last = ex;
                SecurityMetrics.Increment("audit_write_failures_total");
                _logger.LogError(ex, "Audit write failed (attempt {Attempt}). type={Type} outcome={Outcome} code={Code}", attempt + 1, ev.Type, ev.Outcome, ev.Code);

                if (attempt < opts.MaxRetries)
                {
                    await Task.Delay(Math.Max(0, opts.RetryDelayMilliseconds), cancellationToken);
                }
            }
        }

        // Fallback to file to avoid silent loss.
        try
        {
            await AppendToFallbackFileAsync(ev, opts.FallbackFilePath, cancellationToken);
            SecurityMetrics.Increment("audit_fallback_writes_total");
        }
        catch (Exception ex)
        {
            SecurityMetrics.Increment("audit_fallback_failures_total");
            _logger.LogCritical(ex, "Audit fallback write failed.");
        }

        if (opts.FailClosed)
        {
            throw new InvalidOperationException("Audit persistence failed", last);
        }
    }

    private static async Task AppendToFallbackFileAsync(AuthEvent ev, string? path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        var fullPath = Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);

        var json = JsonSerializer.Serialize(ev);
        await File.AppendAllTextAsync(fullPath, json + Environment.NewLine, ct);
    }
}
