namespace Birdsoft.Security.Abstractions.RateLimiting;

using Birdsoft.Security.Abstractions.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Threading.RateLimiting;

public sealed class TenantIpRateLimiterGate : IRateLimiterGate
{
    private readonly IOptionsMonitor<RateLimitingOptions> _options;

    // Limiter caches (partition -> limiter)
    private readonly ConcurrentDictionary<string, TokenBucketRateLimiter> _tenantLimiters = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TokenBucketRateLimiter> _ipLimiters = new(StringComparer.Ordinal);

    public TenantIpRateLimiterGate(IOptionsMonitor<RateLimitingOptions> options)
    {
        _options = options;
    }

    public ValueTask<RateLimitDecision> TryAcquireAsync(HttpContext http, string policyName, CancellationToken cancellationToken = default)
    {
        var opts = _options.CurrentValue;
        if (!opts.Enabled)
        {
            return ValueTask.FromResult(new RateLimitDecision(true, null));
        }

        // PolicyName reserved for future (e.g. different buckets). For now use one.
        _ = policyName;

        string? tenantId = null;
        if (http.Items.TryGetValue("Birdsoft.Security.TenantContext", out var tenantObj)
            && tenantObj is Birdsoft.Security.Abstractions.Tenancy.TenantContext ctx)
        {
            tenantId = ctx.TenantId.ToString();
        }

        if (string.IsNullOrWhiteSpace(tenantId)
            && http.Request.Headers.TryGetValue("X-Tenant-Id", out var tenantHeader))
        {
            tenantId = tenantHeader.ToString();
        }

        var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // 1) Tenant limiter
        if (opts.Tenant.Enabled)
        {
            var tenantBucket = ResolveTenantBucket(opts, tenantId);
            var tenantKey = string.IsNullOrWhiteSpace(tenantId) ? "(no-tenant)" : tenantId;
            var limiter = _tenantLimiters.GetOrAdd(tenantKey, _ => CreateLimiter(tenantBucket));
            var lease = limiter.AttemptAcquire(1);
            if (!lease.IsAcquired)
            {
                var retry = TryGetRetryAfterSeconds(lease);
                return ValueTask.FromResult(new RateLimitDecision(false, retry));
            }
        }

        // 2) IP limiter
        if (opts.Ip.Enabled)
        {
            var limiter = _ipLimiters.GetOrAdd(ip, _ => CreateLimiter(opts.Ip));
            var lease = limiter.AttemptAcquire(1);
            if (!lease.IsAcquired)
            {
                var retry = TryGetRetryAfterSeconds(lease);
                return ValueTask.FromResult(new RateLimitDecision(false, retry));
            }
        }

        return ValueTask.FromResult(new RateLimitDecision(true, null));
    }

    private static RateLimitBucketOptions ResolveTenantBucket(RateLimitingOptions opts, string? tenantId)
    {
        if (!string.IsNullOrWhiteSpace(tenantId) && opts.TenantOverrides.TryGetValue(tenantId, out var overrideBucket))
        {
            return overrideBucket;
        }

        return opts.Tenant;
    }

    private static TokenBucketRateLimiter CreateLimiter(RateLimitBucketOptions bucket)
    {
        var rpm = Math.Max(1, bucket.RequestsPerMinute);
        var burst = Math.Max(1, bucket.Burst);

        return new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
        {
            TokenLimit = burst,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0,
            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
            TokensPerPeriod = rpm,
            AutoReplenishment = true,
        });
    }

    private static int? TryGetRetryAfterSeconds(RateLimitLease lease)
    {
        if (lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) && retryAfter is TimeSpan ts)
        {
            return Math.Max(1, (int)Math.Ceiling(ts.TotalSeconds));
        }

        return 60;
    }
}
