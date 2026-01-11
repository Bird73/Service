namespace Birdsoft.Security.Data.EfCore;

using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class SecurityDbContext : DbContext
{
    public SecurityDbContext(DbContextOptions<SecurityDbContext> options)
        : base(options)
    {
    }

    public DbSet<TenantEntity> Tenants => Set<TenantEntity>();
    public DbSet<SubjectEntity> Subjects => Set<SubjectEntity>();
    public DbSet<AuthStateEntity> AuthStates => Set<AuthStateEntity>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<ExternalIdentityEntity> ExternalIdentities => Set<ExternalIdentityEntity>();
    public DbSet<LocalAccountEntity> LocalAccounts => Set<LocalAccountEntity>();
    public DbSet<AccessTokenDenylistEntity> AccessTokenDenylist => Set<AccessTokenDenylistEntity>();
    public DbSet<OidcProviderConfigEntity> OidcProviders => Set<OidcProviderConfigEntity>();
    public DbSet<TokenSessionEntity> TokenSessions => Set<TokenSessionEntity>();
    public DbSet<AuthEventEntity> AuthEvents => Set<AuthEventEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TenantEntity>(b =>
        {
            b.ToTable("tenants");
            b.HasKey(x => x.TenantId);
            b.Property(x => x.Name).HasMaxLength(200);
        });

        modelBuilder.Entity<SubjectEntity>(b =>
        {
            b.ToTable("subjects");
            b.HasKey(x => new { x.TenantId, x.OurSubject });
        });

        modelBuilder.Entity<AuthStateEntity>(b =>
        {
            b.ToTable("auth_states");
            b.HasKey(x => x.State);
            b.Property(x => x.State).HasMaxLength(200);
            b.HasIndex(x => x.ExpiresAt);
            b.HasIndex(x => x.UsedAt);
        });

        modelBuilder.Entity<RefreshTokenEntity>(b =>
        {
            b.ToTable("refresh_tokens");
            b.HasKey(x => x.Id);
            b.Property(x => x.TokenHash).HasMaxLength(128);
            b.HasIndex(x => x.TokenHash).IsUnique();
            b.HasIndex(x => new { x.TenantId, x.OurSubject });
            b.HasIndex(x => new { x.TenantId, x.SessionId });
            b.HasIndex(x => x.ExpiresAt);
            b.HasIndex(x => x.RevokedAt);

            // Common query pattern: list/cleanup by tenant+subject and validity window.
            b.HasIndex(x => new { x.TenantId, x.OurSubject, x.RevokedAt, x.ExpiresAt });
        });

        modelBuilder.Entity<ExternalIdentityEntity>(b =>
        {
            b.ToTable("external_identities");
            b.HasKey(x => x.Id);
            b.Property(x => x.Provider).HasMaxLength(64);
            b.Property(x => x.Issuer).HasMaxLength(512);
            b.Property(x => x.ProviderSub).HasMaxLength(256);
            b.Property(x => x.DisabledReason).HasMaxLength(256);
            b.HasIndex(x => new { x.TenantId, x.Provider, x.Issuer, x.ProviderSub }).IsUnique();

            b.HasIndex(x => new { x.TenantId, x.Enabled });

            // Ensure one subject isn't bound to multiple external identities within a tenant.
            b.HasIndex(x => new { x.TenantId, x.OurSubject }).IsUnique();
        });

        modelBuilder.Entity<LocalAccountEntity>(b =>
        {
            b.ToTable("local_accounts");
            b.HasKey(x => x.Id);
            b.Property(x => x.UsernameOrEmail).HasMaxLength(256);
            b.Property(x => x.PasswordHash).HasMaxLength(512);
            b.Property(x => x.PasswordSalt).HasMaxLength(256);
            b.HasIndex(x => new { x.TenantId, x.UsernameOrEmail }).IsUnique();
            b.HasIndex(x => new { x.TenantId, x.OurSubject });
        });

        modelBuilder.Entity<AccessTokenDenylistEntity>(b =>
        {
            b.ToTable("access_token_denylist");
            b.HasKey(x => new { x.TenantId, x.Jti });
            b.Property(x => x.Jti).HasMaxLength(64);
            b.HasIndex(x => x.ExpiresAt);
        });

        modelBuilder.Entity<OidcProviderConfigEntity>(b =>
        {
            b.ToTable("oidc_providers");
            b.HasKey(x => new { x.TenantId, x.Provider });
            b.Property(x => x.Provider).HasMaxLength(64);
            b.Property(x => x.Authority).HasMaxLength(512);
            b.Property(x => x.Issuer).HasMaxLength(512);
            b.Property(x => x.ClientId).HasMaxLength(256);
            b.Property(x => x.ClientSecret).HasMaxLength(512);
            b.Property(x => x.CallbackPath).HasMaxLength(256);
            b.Property(x => x.ScopesJson).HasMaxLength(2048);
            b.HasIndex(x => x.Enabled);
        });

        modelBuilder.Entity<TokenSessionEntity>(b =>
        {
            b.ToTable("token_sessions");
            b.HasKey(x => new { x.TenantId, x.SessionId });
            b.Property(x => x.TerminationReason).HasMaxLength(256);
            b.HasIndex(x => new { x.TenantId, x.OurSubject });
            b.HasIndex(x => x.TerminatedAt);
        });

        modelBuilder.Entity<AuthEventEntity>(b =>
        {
            b.ToTable("auth_events");
            b.HasKey(x => x.Id);
            b.Property(x => x.Outcome).HasMaxLength(64);
            b.Property(x => x.Detail).HasMaxLength(2048);
            b.HasIndex(x => x.OccurredAt);
            b.HasIndex(x => x.TenantId);
            b.HasIndex(x => new { x.TenantId, x.OurSubject });
            b.HasIndex(x => x.SessionId);
            b.HasIndex(x => x.Type);
        });

        base.OnModelCreating(modelBuilder);
    }
}
