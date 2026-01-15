namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Infrastructure.Logging.Abstractions;

public sealed class UnhandledExceptionCapture
{
    private readonly object _gate = new();

    public Exception? LastException { get; private set; }
    public string? LastMessageTemplate { get; private set; }
    public IReadOnlyList<object?> LastArgs { get; private set; } = Array.Empty<object?>();

    public void Capture(Exception? exception, string? messageTemplate, object?[]? args)
    {
        lock (_gate)
        {
            LastException = exception;
            LastMessageTemplate = messageTemplate;
            LastArgs = args is null ? Array.Empty<object?>() : args.ToArray();
        }
    }
}

public sealed class TestAppLogger<T> : IAppLogger<T>
{
    private readonly UnhandledExceptionCapture _capture;

    public TestAppLogger(UnhandledExceptionCapture capture)
        => _capture = capture ?? throw new ArgumentNullException(nameof(capture));

    public bool IsEnabled(LogLevel level) => true;

    public void Log(LogLevel level, Exception? exception, string messageTemplate, params object?[] args)
    {
        if (level >= LogLevel.Error)
        {
            _capture.Capture(exception, messageTemplate, args);
        }
    }
}
