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
    public DbSet<RefreshTokenEntity> RefreshSessions => Set<RefreshTokenEntity>();
    public DbSet<ExternalIdentityEntity> ExternalIdentities => Set<ExternalIdentityEntity>();
    public DbSet<LocalAccountEntity> SubjectCredentials => Set<LocalAccountEntity>();
    public DbSet<AccessTokenDenylistEntity> AccessTokenDenylist => Set<AccessTokenDenylistEntity>();
    public DbSet<OidcProviderConfigEntity> OidcProviders => Set<OidcProviderConfigEntity>();
    public DbSet<AuthEventEntity> AuthEvents => Set<AuthEventEntity>();

    // Authorization (RBAC)
    public DbSet<RoleEntity> Roles => Set<RoleEntity>();
    public DbSet<PermissionEntity> Permissions => Set<PermissionEntity>();
    public DbSet<RolePermissionEntity> RolePermissions => Set<RolePermissionEntity>();
    public DbSet<SubjectRoleEntity> SubjectRoles => Set<SubjectRoleEntity>();
    public DbSet<SubjectPermissionEntity> SubjectPermissions => Set<SubjectPermissionEntity>();
    public DbSet<SubjectScopeEntity> SubjectScopes => Set<SubjectScopeEntity>();
    public DbSet<AuthzTenantVersionEntity> AuthzTenantVersions => Set<AuthzTenantVersionEntity>();

    // Platform products + tenant entitlements
    public DbSet<ProductEntity> Products => Set<ProductEntity>();
    public DbSet<TenantProductEntity> TenantProducts => Set<TenantProductEntity>();

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

            b.Property(x => x.DisplayName).HasMaxLength(200);
            b.HasIndex(x => new { x.TenantId, x.Status });
            b.HasIndex(x => new { x.TenantId, x.UpdatedAt });
        });

        modelBuilder.Entity<AuthStateEntity>(b =>
        {
            b.ToTable("auth_states");
            b.HasKey(x => x.State);
            b.Property(x => x.State).HasMaxLength(200);
            b.Property(x => x.Provider).HasMaxLength(64);
            b.HasIndex(x => new { x.TenantId, x.ExpiresAt });
            b.HasIndex(x => new { x.TenantId, x.UsedAt });
        });

        modelBuilder.Entity<RefreshTokenEntity>(b =>
        {
            // Spec: refresh_sessions (one row per refresh session; rotation creates a new session row)
            b.ToTable("refresh_sessions");
            b.HasKey(x => x.Id);
            b.Property(x => x.TokenHash).HasMaxLength(128);
            b.Property(x => x.TokenLookup).HasMaxLength(32);
            b.Property(x => x.RevocationReason).HasMaxLength(64);

            // Tenant-leading uniqueness/indexes.
            b.HasIndex(x => new { x.TenantId, x.TokenHash }).IsUnique();
            b.HasIndex(x => new { x.TenantId, x.TokenLookup });
            b.HasIndex(x => new { x.TenantId, x.OurSubject });
            b.HasIndex(x => new { x.TenantId, x.SessionId }).IsUnique();
            b.HasIndex(x => new { x.TenantId, x.ExpiresAt });
            b.HasIndex(x => new { x.TenantId, x.RevokedAt });

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

            // Support multiple providers per subject (e.g. Google + Microsoft). Still index for lookup.
            b.HasIndex(x => new { x.TenantId, x.OurSubject });

            b.HasIndex(x => new { x.TenantId, x.Provider });
        });

        modelBuilder.Entity<LocalAccountEntity>(b =>
        {
            // Spec: subject_credentials (self-managed username/password; can be disabled but schema must exist)
            b.ToTable("subject_credentials");
            b.HasKey(x => x.Id);
            b.Property(x => x.UsernameOrEmail).HasMaxLength(256);
            b.Property(x => x.PasswordHash).HasMaxLength(512);
            b.Property(x => x.PasswordSalt).HasMaxLength(256);
            b.HasIndex(x => new { x.TenantId, x.UsernameOrEmail }).IsUnique();

            // One local credential per subject per tenant.
            b.HasIndex(x => new { x.TenantId, x.OurSubject }).IsUnique();

            b.Property(x => x.HashVersion);
            b.Property(x => x.FailedAccessCount);
            b.HasIndex(x => new { x.TenantId, x.LockedUntil });
        });

        modelBuilder.Entity<AccessTokenDenylistEntity>(b =>
        {
            b.ToTable("access_token_denylist");
            b.HasKey(x => new { x.TenantId, x.Jti });
            b.Property(x => x.Jti).HasMaxLength(64);
            b.HasIndex(x => new { x.TenantId, x.ExpiresAt });
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
            b.HasIndex(x => new { x.TenantId, x.Enabled });
        });

        modelBuilder.Entity<AuthEventEntity>(b =>
        {
            // Spec: security_audit_logs (append-only)
            b.ToTable("security_audit_logs");
            b.HasKey(x => x.Id);
            b.Property(x => x.Outcome).HasMaxLength(64);
            b.Property(x => x.Code).HasMaxLength(128);
            b.Property(x => x.Detail).HasMaxLength(2048);

            b.Property(x => x.Provider).HasMaxLength(64);
            b.Property(x => x.Issuer).HasMaxLength(512);
            b.Property(x => x.ErrorCode).HasMaxLength(128);

            b.Property(x => x.CorrelationId).HasMaxLength(64);
            b.Property(x => x.TraceId).HasMaxLength(64);
            b.Property(x => x.Ip).HasMaxLength(64);
            b.Property(x => x.UserAgent).HasMaxLength(256);

            // Tenant-leading indexes.
            b.HasIndex(x => x.TenantId);
            b.HasIndex(x => new { x.TenantId, x.OccurredAt });
            b.HasIndex(x => new { x.TenantId, x.OurSubject });
            b.HasIndex(x => new { x.TenantId, x.OurSubject, x.OccurredAt });
            b.HasIndex(x => new { x.TenantId, x.SessionId });
            b.HasIndex(x => new { x.TenantId, x.Type });

            // Query by event code over time.
            b.HasIndex(x => new { x.TenantId, x.Code, x.OccurredAt });
        });

        // Authorization / RBAC tables
        modelBuilder.Entity<RoleEntity>(b =>
        {
            b.ToTable("roles");
            b.HasKey(x => new { x.TenantId, x.RoleId });
            b.Property(x => x.RoleName).HasMaxLength(128);
            b.Property(x => x.Description).HasMaxLength(512);

            b.HasIndex(x => new { x.TenantId, x.RoleName }).IsUnique();
            b.HasIndex(x => new { x.TenantId, x.UpdatedAt });
        });

        modelBuilder.Entity<PermissionEntity>(b =>
        {
            b.ToTable("permissions");
            b.HasKey(x => x.PermId);
            b.Property(x => x.PermKey).HasMaxLength(256);
            b.Property(x => x.ProductKey).HasMaxLength(64);
            b.Property(x => x.Description).HasMaxLength(512);
            b.HasIndex(x => x.PermKey).IsUnique();

            // Optional: allow listing permissions by product.
            b.HasIndex(x => x.ProductKey);
        });

        modelBuilder.Entity<ProductEntity>(b =>
        {
            b.ToTable("products");
            b.HasKey(x => x.ProductId);
            b.Property(x => x.ProductKey).HasMaxLength(64);
            b.Property(x => x.DisplayName).HasMaxLength(200);
            b.Property(x => x.Description).HasMaxLength(1024);
            b.HasIndex(x => x.ProductKey).IsUnique();
            b.HasIndex(x => x.Status);
        });

        modelBuilder.Entity<TenantProductEntity>(b =>
        {
            b.ToTable("tenant_products");
            b.HasKey(x => new { x.TenantId, x.ProductKey });
            b.Property(x => x.ProductKey).HasMaxLength(64);
            b.Property(x => x.PlanJson).HasMaxLength(4096);
            b.HasIndex(x => new { x.TenantId, x.Status });
            b.HasIndex(x => new { x.TenantId, x.ProductKey, x.Status });
            b.HasIndex(x => new { x.ProductKey, x.Status });
            b.HasIndex(x => new { x.TenantId, x.EndAt });
        });

        modelBuilder.Entity<RolePermissionEntity>(b =>
        {
            b.ToTable("role_permissions");
            b.HasKey(x => new { x.TenantId, x.RoleId, x.PermId });

            b.HasOne<RoleEntity>()
                .WithMany()
                .HasForeignKey(x => new { x.TenantId, x.RoleId })
                .OnDelete(DeleteBehavior.Cascade);

            b.HasOne<PermissionEntity>()
                .WithMany()
                .HasForeignKey(x => x.PermId)
                .OnDelete(DeleteBehavior.Cascade);

            b.HasIndex(x => new { x.TenantId, x.PermId });
        });

        modelBuilder.Entity<SubjectRoleEntity>(b =>
        {
            b.ToTable("subject_roles");
            b.HasKey(x => new { x.TenantId, x.OurSubject, x.RoleId });

            b.HasOne<SubjectEntity>()
                .WithMany()
                .HasForeignKey(x => new { x.TenantId, x.OurSubject })
                .OnDelete(DeleteBehavior.Cascade);

            b.HasOne<RoleEntity>()
                .WithMany()
                .HasForeignKey(x => new { x.TenantId, x.RoleId })
                .OnDelete(DeleteBehavior.Cascade);

            b.HasIndex(x => new { x.TenantId, x.RoleId });
        });

        modelBuilder.Entity<SubjectPermissionEntity>(b =>
        {
            b.ToTable("subject_permissions");
            b.HasKey(x => new { x.TenantId, x.OurSubject, x.PermId });

            b.HasOne<SubjectEntity>()
                .WithMany()
                .HasForeignKey(x => new { x.TenantId, x.OurSubject })
                .OnDelete(DeleteBehavior.Cascade);

            b.HasOne<PermissionEntity>()
                .WithMany()
                .HasForeignKey(x => x.PermId)
                .OnDelete(DeleteBehavior.Cascade);

            b.HasIndex(x => new { x.TenantId, x.PermId });
        });

        modelBuilder.Entity<SubjectScopeEntity>(b =>
        {
            b.ToTable("subject_scopes");
            b.HasKey(x => new { x.TenantId, x.OurSubject, x.ScopeKey });
            b.Property(x => x.ScopeKey).HasMaxLength(128);

            b.HasOne<SubjectEntity>()
                .WithMany()
                .HasForeignKey(x => new { x.TenantId, x.OurSubject })
                .OnDelete(DeleteBehavior.Cascade);

            b.HasIndex(x => new { x.TenantId, x.ScopeKey });
        });

        modelBuilder.Entity<AuthzTenantVersionEntity>(b =>
        {
            b.ToTable("authz_tenant_versions");
            b.HasKey(x => x.TenantId);
            b.HasIndex(x => new { x.TenantId, x.UpdatedAt });
        });

        base.OnModelCreating(modelBuilder);
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        EnforceAppendOnlyAudit();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        EnforceAppendOnlyAudit();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    private void EnforceAppendOnlyAudit()
    {
        // Spec: security_audit_logs is append-only.
        var invalid = ChangeTracker.Entries<AuthEventEntity>()
            .Any(e => e.State is EntityState.Modified or EntityState.Deleted);

        if (invalid)
        {
            throw new InvalidOperationException("security_audit_logs is append-only (Update/Delete are not allowed)");
        }
    }
}
