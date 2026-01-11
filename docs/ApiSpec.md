# Security API 規劃（草案）

> 本文件先列 MVP endpoints 與語意；實作細節（DTO、錯誤碼）可在開始寫 controller 後再細化。

## 1. Routing / Version

- Root group：`/api/v1`
- Auth endpoints：`/api/v1/auth/*`
- AuthZ endpoints：`/api/v1/authz/*`
- 租戶識別：僅允許從 Header（`X-Tenant-Id`）與 JWT claim（`tenant_id`）解析；文件不使用 `{tenantId}` path

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

## 4. Token refresh / revoke

### POST /api/v1/auth/token/refresh
- Body：`{ refreshToken }`
- 行為：驗證 refresh token、token_version、rotation；回傳新 access/refresh

### POST /api/v1/auth/token/revoke
- Body：`{ refreshToken, allDevices }`

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

## 7. Health

### GET /health
