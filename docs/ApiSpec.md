# Security API 規劃（草案）

> 本文件先列 MVP endpoints 與語意；實作細節（DTO、錯誤碼）可在開始寫 controller 後再細化。

## 1. Routing / Version

- Root group：`/api/v1`
- Auth endpoints：`/api/v1/auth/*`
- AuthZ endpoints：`/api/v1/authz/*`
- 租戶識別：僅允許從 Header（`X-Tenant-Id`）與 JWT claim（`tenant_id`）解析；文件不使用 `{tenantId}` path

## 1.1 Cross-cutting rules（狀態治理 / Session / 錯誤碼）

### Tenant / User status

- Authentication API 在發行 token 前會檢查：
	- TenantStatus：非 Active -> `403` + `ApiResponse.Fail("tenant_not_active")`
	- UserStatus：非 Active -> `403` + `ApiResponse.Fail("user_not_active")`

- Token 驗證/refresh 會做更細的狀態回報（適合機器判斷）：
	- tenant：`tenant_suspended` / `tenant_archived`
	- user：`user_disabled` / `user_locked`

### Session（可撤銷）

- Access Token 會包含 `session_id` claim。
- Refresh token 會綁定 session。
- Revoke（含 allDevices）會終止 session；終止後：
	- Access token 驗證失敗：`session_terminated`
	- Refresh 失敗：`session_terminated`

### Audit events（稽核）

- 主要 auth/authz/token flow 會寫入 audit event（EF mode 落到 `auth_events` 表）。
- non-EF mode 會以 no-op store 略過寫入，不影響主流程。

## 2. Password login（自家帳密）

### POST /api/v1/auth/password/login
- Body：`{ username, password }`
- Header：`X-Tenant-Id: <guid>`（未帶 Bearer token 時）
- 回傳：`TokenPair { accessToken, refreshToken, expiresIn }`

### POST /api/v1/auth/password/register
- 尚未實作（預留）

## 3. OIDC/OAuth login（Line/MS/Google）

### GET /api/v1/auth/oidc/{provider}/challenge
- 目的：啟動外部登入 challenge（server-side 產生一次性 state，並做 PKCE/nonce 綁定）
- Header：`X-Tenant-Id: <guid>`

### GET /api/v1/auth/oidc/{provider}/callback?state=...&code=...
- 目的：處理 provider callback，完成 ExternalIdentity mapping，發行 tokens
- 需求：該 `tenant_id` 必須啟用此 `provider`；若 callback 時 provider 被停用，應拒絕並要求改用其他登入方式
- 錯誤：若 provider 未啟用，回 `403` + `ApiResponse.Fail("provider_not_enabled")`
- 錯誤：若外部身份 mapping 已存在但被停用，回 `403` + `ApiResponse.Fail("external_identity_disabled")`

## 4. Token refresh / revoke

### POST /api/v1/auth/token/refresh
- Body：`{ refreshToken }`
- 行為：驗證 refresh token、token_version、rotation；回傳新 access/refresh

常見錯誤（`401`）：
- `invalid_refresh_token`
- `revoked_refresh_token`
- `expired_refresh_token`
- `session_terminated`
- `tenant_suspended` / `tenant_archived`
- `user_disabled` / `user_locked`

### POST /api/v1/auth/token/revoke
- Body：`{ refreshToken, allDevices }`

常見錯誤：
- `401 missing_bearer_token`（未帶 access token）
- `401 invalid_token` / `expired_token` / `revoked_token` / `session_terminated`
- `403 forbidden`（refresh token 不屬於該 subject）

### POST /api/v1/auth/logout
- Legacy alias of `/api/v1/auth/token/revoke`（避免語意重疊，建議新呼叫方一律使用 `/token/revoke`）

## 5. Force re-login（版本號）

### POST /api/v1/auth/token-version/bump
- 尚未實作（預留）

## 6. Authorization

### POST /api/v1/authz/check
- Tenant 來源：JWT claim `tenant_id`（若有）優先，其次 Header `X-Tenant-Id`
- Body：`{ ourSubject, resource, action, context }`
- 回傳：`{ allowed: true/false, reason }`

常見錯誤：
- `400 invalid_request`
- `403 tenant_not_active`
- `403 user_not_active`

## 7. Health

### GET /health
