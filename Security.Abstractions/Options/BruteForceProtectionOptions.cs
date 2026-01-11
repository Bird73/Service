namespace Birdsoft.Security.Abstractions.Options;

/// <summary>
/// 暴力破解防護設定。
/// </summary>
public sealed class BruteForceProtectionOptions
{
    public const string SectionName = "Security:BruteForce";

    public bool Enabled { get; init; } = true;

    /// <summary>統計視窗（秒）</summary>
    public int WindowSeconds { get; init; } = 300;

    /// <summary>觸發延遲的失敗次數門檻</summary>
    public int DelayAfterFailures { get; init; } = 3;

    /// <summary>每次失敗要增加的延遲（毫秒）</summary>
    public int DelayStepMs { get; init; } = 250;

    /// <summary>最大延遲（毫秒）</summary>
    public int MaxDelayMs { get; init; } = 2000;

    /// <summary>觸發封鎖的失敗次數門檻</summary>
    public int MaxFailures { get; init; } = 8;

    /// <summary>封鎖秒數</summary>
    public int BlockSeconds { get; init; } = 120;
}
