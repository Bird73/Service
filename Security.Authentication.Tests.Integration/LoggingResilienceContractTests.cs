namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Infrastructure.Logging.Abstractions;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

public sealed class LoggingResilienceContractTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static void TryDeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        for (var i = 0; i < 5; i++)
        {
            try
            {
                File.Delete(path);
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(50);
            }
            catch (UnauthorizedAccessException)
            {
                Thread.Sleep(50);
            }
        }
    }

    private static string CreateTempSqliteDbPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), "Birdsoft.Security.Authentication.Tests");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"security-{Guid.NewGuid():N}.db");
    }

    private static async Task EnsureDbCreatedAsync(WebApplicationFactory<Program> factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    private sealed class ThrowingAuthEventStore : IAuthEventStore
    {
        public Task AppendAsync(Birdsoft.Security.Abstractions.Models.AuthEvent ev, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("boom: auth event store");

        public Task<IReadOnlyList<Birdsoft.Security.Abstractions.Models.AuthEvent>> QueryAsync(Birdsoft.Security.Abstractions.Models.AuthEventQuery query, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("boom: auth event store");
    }

    private sealed class ThrowingBruteForceProtection : IBruteForceProtection
    {
        public ValueTask<BruteForceDecision> CheckAsync(Guid tenantId, string username, string ip, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("boom: brute force");

        public ValueTask RecordFailureAsync(Guid tenantId, string username, string ip, string reason, CancellationToken cancellationToken = default)
            => ValueTask.CompletedTask;

        public ValueTask RecordSuccessAsync(Guid tenantId, string username, string ip, CancellationToken cancellationToken = default)
            => ValueTask.CompletedTask;
    }

    private sealed class UnhandledExceptionCapture
    {
        private readonly object _gate = new();

        public Exception? LastException { get; private set; }
        public string? LastMessageTemplate { get; private set; }

        public void Capture(Exception? exception, string? messageTemplate)
        {
            lock (_gate)
            {
                LastException = exception;
                LastMessageTemplate = messageTemplate;
            }
        }
    }

    private sealed class CapturingAppLogger<T> : IAppLogger<T>
    {
        private readonly UnhandledExceptionCapture _capture;

        public CapturingAppLogger(UnhandledExceptionCapture capture)
            => _capture = capture;

        public bool IsEnabled(LogLevel level) => true;

        public void Log(LogLevel level, Exception? exception, string messageTemplate, params object?[] args)
        {
            if (level >= LogLevel.Error)
            {
                _capture.Capture(exception, messageTemplate);
            }
        }
    }

    private sealed class ThrowingAppLogger<T> : IAppLogger<T>
    {
        public bool IsEnabled(LogLevel level) => true;

        public void Log(LogLevel level, Exception? exception, string messageTemplate, params object?[] args)
            => throw new InvalidOperationException("boom: logger");
    }

    [Fact]
    public async Task PasswordLogin_When_AuditStore_Throws_And_PasswordWrong_Still_Returns_401_InvalidCredentials()
    {
        var tenantId = Guid.NewGuid();

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            AuthEvents = new ThrowingAuthEventStore(),
            Tenants = new StubTenantRepository(new TenantDto { TenantId = tenantId, Name = "t", Status = TenantStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(true, TimeSpan.Zero, null)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Fail(AuthErrorCodes.InvalidCredentials)),
        });

        var client = factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
        {
            Content = JsonContent.Create(new LoginRequest(Username: "alice", Password: "bad")),
        };
        req.Headers.Add("X-Tenant-Id", tenantId.ToString());

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.Equal(AuthErrorCodes.InvalidCredentials, body.Error!.Code);
    }

    [Fact]
    public async Task PasswordLogin_When_AuditStore_Throws_Returns_400_InvalidRequest()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";
        WebApplicationFactory<Program>? factory = null;
        HttpClient? client = null;

        try
        {
            factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
            {
                SecurityDbConnectionString = cs,
                AuthEvents = new ThrowingAuthEventStore(),
            });

            client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();

            var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "", Password: "")),
            };
            req.Headers.Add("X-Tenant-Id", tenantId.ToString());

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal(AuthErrorCodes.InvalidRequest, body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task UnhandledException_When_Logger_Throws_Still_Returns_500_InternalError()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";
        WebApplicationFactory<Program>? factory = null;
        HttpClient? client = null;

        try
        {
            factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
            {
                SecurityDbConnectionString = cs,
                BruteForce = new ThrowingBruteForceProtection(),
            }).WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll(typeof(IAppLogger<>));
                    services.AddTransient(typeof(IAppLogger<>), typeof(ThrowingAppLogger<>));
                });
            });

            client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            using (var scope = factory.Services.CreateScope())
            {
                var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
                _ = await tokens.GenerateTokensAsync(tenantId, Guid.NewGuid());
            }

            var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "u", Password: "p")),
            };
            req.Headers.Add("X-Tenant-Id", tenantId.ToString());

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.InternalServerError, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal(AuthErrorCodes.InternalError, body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task UnhandledException_Invokes_ErrorLogger()
    {
        var dbPath = CreateTempSqliteDbPath();
        var cs = $"Data Source={dbPath}";

        WebApplicationFactory<Program>? factory = null;
        HttpClient? client = null;

        try
        {
            var capture = new UnhandledExceptionCapture();

            factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
            {
                SecurityDbConnectionString = cs,
                BruteForce = new ThrowingBruteForceProtection(),
            }).WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    services.AddSingleton(capture);
                    services.RemoveAll(typeof(IAppLogger<>));
                    services.AddTransient(typeof(IAppLogger<>), typeof(CapturingAppLogger<>));
                });
            });

            client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            using (var scope = factory.Services.CreateScope())
            {
                var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
                _ = await tokens.GenerateTokensAsync(tenantId, Guid.NewGuid());
            }

            var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login")
            {
                Content = JsonContent.Create(new LoginRequest(Username: "u", Password: "p")),
            };
            req.Headers.Add("X-Tenant-Id", tenantId.ToString());

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.InternalServerError, res.StatusCode);

            Assert.NotNull(capture.LastException);
            Assert.Contains("Unhandled exception", capture.LastMessageTemplate ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }
}
