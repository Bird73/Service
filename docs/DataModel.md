# Company.Security 資料模型規劃（草案）

> 目標：以資料庫約束保證 tenant 隔離與 identity mapping 規則。

## 1. 主要表

### Tenants
- `tenant_id` (PK, GUID)
- `name`
- `token_version`（tenant 強制重新登入用）
- `created_at`

### Subjects
- `(tenant_id, our_subject)` (PK composite)
- `token_version`（subject 強制重新登入用）
- `created_at`

### LocalAccounts（tenant-scoped）
- `id` (PK)
- `tenant_id`
- `our_subject`
- `username_or_email`
- `password_hash`
- `created_at`

索引/唯一：
- UNIQUE `(tenant_id, username_or_email)`
- FK `(tenant_id, our_subject)` -> Subjects

### ExternalIdentities（OIDC/OAuth mapping）
- `id` (PK)
- `tenant_id`
- `our_subject`
- `provider`（line/ms/google…）
- `issuer`
- `provider_sub`
- `created_at`

索引/唯一（關鍵）：
- UNIQUE `(tenant_id, provider, issuer, provider_sub)`
- UNIQUE `(tenant_id, our_subject)`  ← 確保同 tenant 不可多 provider 綁同 subject

### OidcProviderSettings（全域 provider 設定）

需求已確認：每個 provider 使用同一組 clientId（不因 tenant 而異），但 tenant 可停用 provider。

- `provider` (PK)（line/ms/google…）
- `client_id`
- `client_secret`
- `issuer`（如 OIDC issuer）
- `authorization_endpoint` / `token_endpoint` / `userinfo_endpoint`（視採用的 library 決定是否需要自存）
- `enabled`（全域開關）

### TenantEnabledProviders（逐租戶啟用 provider）

- `(tenant_id, provider)` (PK)
- `enabled`（可選；若 PK 存在即代表啟用，也可用欄位軟停用）

索引/唯一：
- PK `(tenant_id, provider)`

### AuthStates（一次性 state）
- `state` (PK)
- `tenant_id`
- `created_at`
- `expires_at`（now+5m）
- `used_at`（null 代表未使用）

索引：
- INDEX `(expires_at)`

### RefreshTokens（只存 hash）
- `id` (PK)
- `tenant_id`
- `our_subject`
- `token_hash`
- `created_at`
- `expires_at`
- `revoked_at`（null 代表有效）
- `replaced_by_refresh_token_id`（rotation）
- `issued_tenant_tv` / `issued_subject_tv`（簽發當下版本，用於 refresh 驗證）

索引：
- UNIQUE `(token_hash)`
- INDEX `(tenant_id, our_subject, revoked_at, expires_at)`

## 2. 授權（Role/Permission）

最小可行二擇一：

A) Role-based
- Roles: `(tenant_id, role_id)`
- SubjectRoles: `(tenant_id, our_subject, role_id)`
- RolePermissions: `(tenant_id, role_id, permission)`

B) Direct permissions
- SubjectPermissions: `(tenant_id, our_subject, permission)`

## 3. 交易一致性建議

- OIDC callback 首次登入：建立 Subject + ExternalIdentity 必須在同一交易，避免重複建立。
- Refresh rotation：寫入新 refresh、撤銷舊 refresh 必須同交易。

