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
        });

        modelBuilder.Entity<ExternalIdentityEntity>(b =>
        {
            b.ToTable("external_identities");
            b.HasKey(x => x.Id);
            b.Property(x => x.Provider).HasMaxLength(64);
            b.Property(x => x.Issuer).HasMaxLength(512);
            b.Property(x => x.ProviderSub).HasMaxLength(256);
            b.HasIndex(x => new { x.TenantId, x.Provider, x.Issuer, x.ProviderSub }).IsUnique();
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

        base.OnModelCreating(modelBuilder);
    }
}
