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

- 主要 auth/authz/token flow 會寫入 audit event（EF mode 落到 `security_audit_logs` 表）。
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
- 行為（安全性）：
	- server-side 建立一次性 `state`（5 分鐘有效）
	- `state` 需綁定：`tenant_id` + `provider` + `nonce` + `code_verifier`（PKCE）
	- 成功時通常以 `302` redirect 到 provider authorization url（含 `state` 與 `code_challenge`）

### GET /api/v1/auth/oidc/{provider}/callback?state=...&code=...
- 目的：處理 provider callback，完成 ExternalIdentity mapping，發行 tokens
- 需求：該 `tenant_id` 必須啟用此 `provider`；若 callback 時 provider 被停用，應拒絕並要求改用其他登入方式
- 錯誤：若 provider 未啟用，回 `403` + `ApiResponse.Fail("provider_not_enabled")`
- 錯誤：若外部身份 mapping 已存在但被停用，回 `403` + `ApiResponse.Fail("external_identity_disabled")`
- 安全性驗證（callback）：
	- 先 `consume` state（一次性），避免重放；任何結果都不允許重用同一 state
	- 若 request 有帶 `X-Tenant-Id`，必須等於 state 綁定的 `tenant_id`，否則回 `400` + `invalid_state`（避免洩漏 state 所屬 tenant）
	- path `{provider}` 必須等於 state 綁定的 provider，否則回 `400` + `invalid_state`
	- nonce 驗證失敗回 `400` + `invalid_nonce`
	- PKCE（code_verifier）驗證失敗回 `400` + `invalid_pkce`

## 4. Token refresh / revoke

### POST /api/v1/auth/token/refresh
- Body：`{ refreshToken }`
- 行為：驗證 refresh token、token_version、rotation；回傳新 access/refresh

補充（併發與 rotation 行為）：
- 同一顆 refresh token 併發呼叫 `/token/refresh` 時，只允許其中一個成功；另一個回 `401`。
	- 若輸家發生在「同交易 rotation 競態」：回 `revoked_refresh_token`（防雙花；通常不終止 session）。
	- 若輸家讀到「已 rotation 的舊 token」（`replaced_by` != null）：可能視為 reuse attack，回 `refresh_token_reuse_detected` 並終止 session（要求重新登入）。
- rotation 後舊 refresh token（`replaced_by` != null）再次被使用，視為可能被竊，回 `401` + `refresh_token_reuse_detected`，並終止該 session（要求重新登入）。

常見錯誤（`401`）：
- `invalid_refresh_token`
- `revoked_refresh_token`
- `expired_refresh_token`
- `refresh_token_reuse_detected`
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

> 本章節包含兩類管理 API：
> - Platform Admin：控制「租戶可用哪些系統（Products / TenantProducts entitlement）」
> - Tenant Admin：僅能在「租戶已啟用的系統」內做授權管理（Entitlement 為 RBAC 前置條件）

### POST /api/v1/authz/check
- Tenant 來源：JWT claim `tenant_id`（若有）優先，其次 Header `X-Tenant-Id`
- Body：`{ ourSubject, resource, action, context }`
- 回傳：`{ allowed: true/false, reason }`

常見錯誤：
- `400 invalid_request`
- `403 tenant_not_active`
- `403 user_not_active`

### 6.1 Platform Administration APIs（Platform Admin）

> 用途：平台管理者維護 Products（全域產品目錄）以及 TenantProducts（租戶 entitlement）。
>
> 與授權流程的關係：Entitlement 是授權前置條件（Entitlement -> RBAC）。

共通規則：
- Auth：Bearer token
- Policy：`PlatformAdminOnly`（僅 PlatformAdmin 可存取）

#### GET /api/v1/platform/products
- 存取：僅 `PlatformAdminOnly`
- 用途：列出平台產品（Products）
- Query（optional）：
	- `status`：產品狀態篩選
	- `skip` / `take`
- 回傳：`ApiResponse<List<{ productKey, displayName, description, status, createdAt, updatedAt }>>`

#### POST /api/v1/platform/products
- 存取：僅 `PlatformAdminOnly`
- 用途：建立產品（Products）
- Body：`{ productKey, displayName, description?, status? }`
- 回傳：
	- `201 Created`：`ApiResponse.Ok(product)`

常見錯誤：
- `400 invalid_request`（欄位缺漏/不合法）
- `409 conflict`（productKey 已存在）

#### GET /api/v1/platform/tenants/{tenantId}/products
- 存取：僅 `PlatformAdminOnly`
- 用途：列出某租戶的產品 entitlement（TenantProducts；包含 displayName 以便管理 UI 顯示）
- 回傳：`ApiResponse<List<{ tenantId, productKey, displayName?, status, startAt, endAt, planJson?, createdAt, updatedAt }>>`

#### PUT /api/v1/platform/tenants/{tenantId}/products/{productKey}
- 存取：僅 `PlatformAdminOnly`
- 用途：新增或更新租戶的產品 entitlement（TenantProducts upsert）
- Body：`{ status?, startAt?, endAt?, planJson? }`
- 行為：
	- 若該租戶尚無 entitlement，會建立一筆 tenant_products
	- 若已存在，會更新狀態與時間窗
	- Entitlement 變更會即時影響 Tenant Admin 授權管理 API 及授權判斷鏈

常見錯誤：
- `400 invalid_request`（productKey 缺漏/不合法）
- `404 not_found`（product 不存在）

#### DELETE /api/v1/platform/tenants/{tenantId}/products/{productKey}
- 存取：僅 `PlatformAdminOnly`
- 用途：移除租戶的產品 entitlement（刪除 tenant_products 該筆）
- 回傳：
	- `204 No Content`：刪除成功
	- `404 Not Found`：該租戶/產品 entitlement 不存在

---

### 6.2 Tenant Administration APIs（Tenant Admin；Entitlement 強制門禁）

> 用途：租戶管理者查詢租戶已啟用之產品與 permissions，並調整使用者的「直授（direct）permission」。
>
> 重要規則（必須一致）：
> - Tenant Admin 僅能操作 tenant 已啟用（enabled 且在有效期間）的 Product。
> - 若 permission 所屬 product 未啟用（或不在有效期間），API 必須回 `403 Forbidden`（error code：`product_not_enabled`）。
> - Entitlement 檢查為 RBAC 前置條件（不得退回 RBAC 允許）。

共通規則：
- Auth：Bearer token（必須有 `tenant_id` claim）
- Policy：`AdminOnly`（僅 Tenant Admin 可存取）

#### GET /api/v1/tenant/products
- 存取：僅 `AdminOnly`（Tenant Admin）
- 用途：列出「目前 tenant 已啟用」的 products（可作為管理 UI 的選單來源）
- 回傳：`ApiResponse<List<{ tenantId, productKey, displayName, status, startAt, endAt, planJson?, createdAt, updatedAt }>>`

常見錯誤：
- `400 invalid_request`（token 缺少 tenant_id claim）
- `403 forbidden`（未具備 Tenant Admin 權限）

#### GET /api/v1/tenant/permissions?productKey=
- 存取：僅 `AdminOnly`（Tenant Admin）
- 用途：列出 tenant 可用的 permissions
- Query：
	- `productKey`（optional）
		- 有帶：僅列該產品的 permissions（但必須先通過 entitlement 門禁）
		- 未帶：列出「目前 tenant 已啟用產品」的 permissions（會排除未啟用產品）
- 回傳：`ApiResponse<List<{ permissionKey, productKey, description }>>`

常見錯誤：
- `400 invalid_request`（token 缺少 tenant_id claim）
- `403 forbidden`
- `403 product_not_enabled`

#### POST /api/v1/tenant/users/{userId}/permissions
- 存取：僅 `AdminOnly`（Tenant Admin）
- 用途：新增使用者的 direct permission
- Body：`{ permissionKey, reason? }`
- 行為：
	- 先由 permissionKey 查出 productKey
	- 再檢查 tenant 是否啟用該 product（含時間窗）
	- 通過才會更新 subject 的 direct permissions（不影響既有 roles/scopes）

常見錯誤：
- `400 invalid_request`
- `403 forbidden`
- `403 product_not_enabled`
- `404 not_found`（permission 不存在或 user 不存在）

#### DELETE /api/v1/tenant/users/{userId}/permissions/{permissionKey}
- 存取：僅 `AdminOnly`（Tenant Admin）
- 用途：移除使用者的 direct permission
- 行為：同上（先 entitlement gate，再移除 direct permission；不影響既有 roles/scopes）

常見錯誤：
- `400 invalid_request`
- `403 forbidden`
- `403 product_not_enabled`
- `404 not_found`（permission 不存在或 user 不存在）

## 7. Health

### GET /health
