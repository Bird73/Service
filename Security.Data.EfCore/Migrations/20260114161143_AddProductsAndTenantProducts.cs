using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Security.Data.EfCore.Migrations
{
    /// <inheritdoc />
    public partial class AddProductsAndTenantProducts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "access_token_denylist",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Jti = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_access_token_denylist", x => new { x.TenantId, x.Jti });
                });

            migrationBuilder.CreateTable(
                name: "auth_states",
                columns: table => new
                {
                    State = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    Provider = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CodeVerifier = table.Column<string>(type: "TEXT", nullable: true),
                    Nonce = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_auth_states", x => x.State);
                });

            migrationBuilder.CreateTable(
                name: "authz_tenant_versions",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ModelVersion = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_authz_tenant_versions", x => x.TenantId);
                });

            migrationBuilder.CreateTable(
                name: "external_identities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OurSubject = table.Column<Guid>(type: "TEXT", nullable: false),
                    Provider = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Issuer = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    ProviderSub = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    DisabledAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    DisabledReason = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_external_identities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "oidc_providers",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Provider = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    Authority = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    Issuer = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    ClientSecret = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    CallbackPath = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    ScopesJson = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_oidc_providers", x => new { x.TenantId, x.Provider });
                });

            migrationBuilder.CreateTable(
                name: "permissions",
                columns: table => new
                {
                    PermId = table.Column<Guid>(type: "TEXT", nullable: false),
                    PermKey = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    ProductKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Description = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_permissions", x => x.PermId);
                });

            migrationBuilder.CreateTable(
                name: "products",
                columns: table => new
                {
                    ProductId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProductKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_products", x => x.ProductId);
                });

            migrationBuilder.CreateTable(
                name: "refresh_sessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OurSubject = table.Column<Guid>(type: "TEXT", nullable: false),
                    SessionId = table.Column<Guid>(type: "TEXT", nullable: false),
                    TokenHash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    TokenLookup = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    RevokedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    ReplacedByRefreshTokenId = table.Column<Guid>(type: "TEXT", nullable: true),
                    RevocationReason = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    IssuedTenantTokenVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    IssuedSubjectTokenVersion = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refresh_sessions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "roles",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RoleId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RoleName = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_roles", x => new { x.TenantId, x.RoleId });
                });

            migrationBuilder.CreateTable(
                name: "security_audit_logs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    OccurredAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: true),
                    OurSubject = table.Column<Guid>(type: "TEXT", nullable: true),
                    SessionId = table.Column<Guid>(type: "TEXT", nullable: true),
                    Type = table.Column<int>(type: "INTEGER", nullable: false),
                    Outcome = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Provider = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Issuer = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    ErrorCode = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    Code = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    Detail = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    CorrelationId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    TraceId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    UserAgent = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    MetaJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_audit_logs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "subject_credentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OurSubject = table.Column<Guid>(type: "TEXT", nullable: false),
                    UsernameOrEmail = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    PasswordHash = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    PasswordSalt = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    PasswordIterations = table.Column<int>(type: "INTEGER", nullable: false),
                    HashVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    LastPasswordChangeAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    FailedAccessCount = table.Column<int>(type: "INTEGER", nullable: false),
                    LockedUntil = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_subject_credentials", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "subjects",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OurSubject = table.Column<Guid>(type: "TEXT", nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    TokenVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_subjects", x => new { x.TenantId, x.OurSubject });
                });

            migrationBuilder.CreateTable(
                name: "tenant_products",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProductKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    StartAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    EndAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    PlanJson = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tenant_products", x => new { x.TenantId, x.ProductKey });
                });

            migrationBuilder.CreateTable(
                name: "tenants",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    TokenVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tenants", x => x.TenantId);
                });

            migrationBuilder.CreateTable(
                name: "role_permissions",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RoleId = table.Column<Guid>(type: "TEXT", nullable: false),
                    PermId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AssignedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_role_permissions", x => new { x.TenantId, x.RoleId, x.PermId });
                    table.ForeignKey(
                        name: "FK_role_permissions_permissions_PermId",
                        column: x => x.PermId,
                        principalTable: "permissions",
                        principalColumn: "PermId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_role_permissions_roles_TenantId_RoleId",
                        columns: x => new { x.TenantId, x.RoleId },
                        principalTable: "roles",
                        principalColumns: new[] { "TenantId", "RoleId" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "subject_permissions",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OurSubject = table.Column<Guid>(type: "TEXT", nullable: false),
                    PermId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AssignedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_subject_permissions", x => new { x.TenantId, x.OurSubject, x.PermId });
                    table.ForeignKey(
                        name: "FK_subject_permissions_permissions_PermId",
                        column: x => x.PermId,
                        principalTable: "permissions",
                        principalColumn: "PermId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_subject_permissions_subjects_TenantId_OurSubject",
                        columns: x => new { x.TenantId, x.OurSubject },
                        principalTable: "subjects",
                        principalColumns: new[] { "TenantId", "OurSubject" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "subject_roles",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OurSubject = table.Column<Guid>(type: "TEXT", nullable: false),
                    RoleId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AssignedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_subject_roles", x => new { x.TenantId, x.OurSubject, x.RoleId });
                    table.ForeignKey(
                        name: "FK_subject_roles_roles_TenantId_RoleId",
                        columns: x => new { x.TenantId, x.RoleId },
                        principalTable: "roles",
                        principalColumns: new[] { "TenantId", "RoleId" },
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_subject_roles_subjects_TenantId_OurSubject",
                        columns: x => new { x.TenantId, x.OurSubject },
                        principalTable: "subjects",
                        principalColumns: new[] { "TenantId", "OurSubject" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "subject_scopes",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OurSubject = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScopeKey = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    AssignedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_subject_scopes", x => new { x.TenantId, x.OurSubject, x.ScopeKey });
                    table.ForeignKey(
                        name: "FK_subject_scopes_subjects_TenantId_OurSubject",
                        columns: x => new { x.TenantId, x.OurSubject },
                        principalTable: "subjects",
                        principalColumns: new[] { "TenantId", "OurSubject" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_access_token_denylist_TenantId_ExpiresAt",
                table: "access_token_denylist",
                columns: new[] { "TenantId", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_auth_states_TenantId_ExpiresAt",
                table: "auth_states",
                columns: new[] { "TenantId", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_auth_states_TenantId_UsedAt",
                table: "auth_states",
                columns: new[] { "TenantId", "UsedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_authz_tenant_versions_TenantId_UpdatedAt",
                table: "authz_tenant_versions",
                columns: new[] { "TenantId", "UpdatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_external_identities_TenantId_Enabled",
                table: "external_identities",
                columns: new[] { "TenantId", "Enabled" });

            migrationBuilder.CreateIndex(
                name: "IX_external_identities_TenantId_OurSubject",
                table: "external_identities",
                columns: new[] { "TenantId", "OurSubject" });

            migrationBuilder.CreateIndex(
                name: "IX_external_identities_TenantId_Provider",
                table: "external_identities",
                columns: new[] { "TenantId", "Provider" });

            migrationBuilder.CreateIndex(
                name: "IX_external_identities_TenantId_Provider_Issuer_ProviderSub",
                table: "external_identities",
                columns: new[] { "TenantId", "Provider", "Issuer", "ProviderSub" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_oidc_providers_TenantId_Enabled",
                table: "oidc_providers",
                columns: new[] { "TenantId", "Enabled" });

            migrationBuilder.CreateIndex(
                name: "IX_permissions_PermKey",
                table: "permissions",
                column: "PermKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_permissions_ProductKey",
                table: "permissions",
                column: "ProductKey");

            migrationBuilder.CreateIndex(
                name: "IX_products_ProductKey",
                table: "products",
                column: "ProductKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_products_Status",
                table: "products",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_TenantId_ExpiresAt",
                table: "refresh_sessions",
                columns: new[] { "TenantId", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_TenantId_OurSubject",
                table: "refresh_sessions",
                columns: new[] { "TenantId", "OurSubject" });

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_TenantId_OurSubject_RevokedAt_ExpiresAt",
                table: "refresh_sessions",
                columns: new[] { "TenantId", "OurSubject", "RevokedAt", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_TenantId_RevokedAt",
                table: "refresh_sessions",
                columns: new[] { "TenantId", "RevokedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_TenantId_SessionId",
                table: "refresh_sessions",
                columns: new[] { "TenantId", "SessionId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_TenantId_TokenHash",
                table: "refresh_sessions",
                columns: new[] { "TenantId", "TokenHash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_TenantId_TokenLookup",
                table: "refresh_sessions",
                columns: new[] { "TenantId", "TokenLookup" });

            migrationBuilder.CreateIndex(
                name: "IX_role_permissions_PermId",
                table: "role_permissions",
                column: "PermId");

            migrationBuilder.CreateIndex(
                name: "IX_role_permissions_TenantId_PermId",
                table: "role_permissions",
                columns: new[] { "TenantId", "PermId" });

            migrationBuilder.CreateIndex(
                name: "IX_roles_TenantId_RoleName",
                table: "roles",
                columns: new[] { "TenantId", "RoleName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_roles_TenantId_UpdatedAt",
                table: "roles",
                columns: new[] { "TenantId", "UpdatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_security_audit_logs_TenantId",
                table: "security_audit_logs",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_security_audit_logs_TenantId_Code_OccurredAt",
                table: "security_audit_logs",
                columns: new[] { "TenantId", "Code", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_security_audit_logs_TenantId_OccurredAt",
                table: "security_audit_logs",
                columns: new[] { "TenantId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_security_audit_logs_TenantId_OurSubject",
                table: "security_audit_logs",
                columns: new[] { "TenantId", "OurSubject" });

            migrationBuilder.CreateIndex(
                name: "IX_security_audit_logs_TenantId_OurSubject_OccurredAt",
                table: "security_audit_logs",
                columns: new[] { "TenantId", "OurSubject", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_security_audit_logs_TenantId_SessionId",
                table: "security_audit_logs",
                columns: new[] { "TenantId", "SessionId" });

            migrationBuilder.CreateIndex(
                name: "IX_security_audit_logs_TenantId_Type",
                table: "security_audit_logs",
                columns: new[] { "TenantId", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_subject_credentials_TenantId_LockedUntil",
                table: "subject_credentials",
                columns: new[] { "TenantId", "LockedUntil" });

            migrationBuilder.CreateIndex(
                name: "IX_subject_credentials_TenantId_OurSubject",
                table: "subject_credentials",
                columns: new[] { "TenantId", "OurSubject" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_subject_credentials_TenantId_UsernameOrEmail",
                table: "subject_credentials",
                columns: new[] { "TenantId", "UsernameOrEmail" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_subject_permissions_PermId",
                table: "subject_permissions",
                column: "PermId");

            migrationBuilder.CreateIndex(
                name: "IX_subject_permissions_TenantId_PermId",
                table: "subject_permissions",
                columns: new[] { "TenantId", "PermId" });

            migrationBuilder.CreateIndex(
                name: "IX_subject_roles_TenantId_RoleId",
                table: "subject_roles",
                columns: new[] { "TenantId", "RoleId" });

            migrationBuilder.CreateIndex(
                name: "IX_subject_scopes_TenantId_ScopeKey",
                table: "subject_scopes",
                columns: new[] { "TenantId", "ScopeKey" });

            migrationBuilder.CreateIndex(
                name: "IX_subjects_TenantId_Status",
                table: "subjects",
                columns: new[] { "TenantId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_subjects_TenantId_UpdatedAt",
                table: "subjects",
                columns: new[] { "TenantId", "UpdatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_tenant_products_ProductKey_Status",
                table: "tenant_products",
                columns: new[] { "ProductKey", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_tenant_products_TenantId_EndAt",
                table: "tenant_products",
                columns: new[] { "TenantId", "EndAt" });

            migrationBuilder.CreateIndex(
                name: "IX_tenant_products_TenantId_ProductKey_Status",
                table: "tenant_products",
                columns: new[] { "TenantId", "ProductKey", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_tenant_products_TenantId_Status",
                table: "tenant_products",
                columns: new[] { "TenantId", "Status" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "access_token_denylist");

            migrationBuilder.DropTable(
                name: "auth_states");

            migrationBuilder.DropTable(
                name: "authz_tenant_versions");

            migrationBuilder.DropTable(
                name: "external_identities");

            migrationBuilder.DropTable(
                name: "oidc_providers");

            migrationBuilder.DropTable(
                name: "products");

            migrationBuilder.DropTable(
                name: "refresh_sessions");

            migrationBuilder.DropTable(
                name: "role_permissions");

            migrationBuilder.DropTable(
                name: "security_audit_logs");

            migrationBuilder.DropTable(
                name: "subject_credentials");

            migrationBuilder.DropTable(
                name: "subject_permissions");

            migrationBuilder.DropTable(
                name: "subject_roles");

            migrationBuilder.DropTable(
                name: "subject_scopes");

            migrationBuilder.DropTable(
                name: "tenant_products");

            migrationBuilder.DropTable(
                name: "tenants");

            migrationBuilder.DropTable(
                name: "permissions");

            migrationBuilder.DropTable(
                name: "roles");

            migrationBuilder.DropTable(
                name: "subjects");
        }
    }
}
