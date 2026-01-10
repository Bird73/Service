# Company.Security API 規劃（草案）

> 本文件先列 MVP endpoints 與語意；實作細節（DTO、錯誤碼）可在開始寫 controller 後再細化。

## 1. State（Tenant-aware，5 分鐘一次性）

### POST /api/tenants/{tenantId}/auth/state
- 目的：建立一次性 state（TTL 5 分鐘）
- 回傳：`{ state, expires_at }`

### POST /api/auth/state/cleanup
- 目的：清理過期/已用 state（可限制僅內部/管理用）

## 2. Password login（自家帳密）

### POST /api/auth/password/login
- Body：`{ tenant_id, username_or_email, password }`
- 回傳：`{ access_token, refresh_token, expires_in }`

### POST /api/auth/password/register
- Body：`{ tenant_id, username_or_email, password }`
- 規則：tenant-scoped，不做跨 tenant 去重

## 3. OIDC/OAuth login（Line/MS/Google）

### GET /api/auth/oidc/{provider}/start?state=...
- 目的：啟動外部登入 challenge
- 需求：state 必須存在且未過期/未使用
- 需求：該 `tenant_id` 必須啟用此 `provider`（TenantEnabledProviders）

### GET /api/auth/oidc/{provider}/callback?state=...&code=...
- 目的：處理 provider callback，完成 ExternalIdentity mapping，發行 tokens
- 需求：該 `tenant_id` 必須啟用此 `provider`；若 callback 時 provider 被停用，應拒絕並要求改用其他登入方式

## 4. Token refresh / revoke

### POST /api/auth/token/refresh
- Body：`{ refresh_token }`
- 行為：驗證 refresh token、token_version、rotation；回傳新 access/refresh

### POST /api/auth/token/revoke
- Body：`{ refresh_token }`（或 `{ jti }` 進階）

## 5. Force re-login（版本號）

### POST /api/tenants/{tenantId}/token-version/bump
- 目的：tenant 級別強制重新登入

### POST /api/tenants/{tenantId}/subjects/{ourSubject}/token-version/bump
- 目的：user/subject 級別強制重新登入

## 6. Authorization

### POST /api/authz/check
- Body：`{ tenant_id, our_subject, permission }`
- 回傳：`{ allowed: true/false }`

## 7. Health

### GET /health
