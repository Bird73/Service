# Security 微服務規劃（Authentication + JWT + Authorization）

## 1. 目標與設計原則

- 平台：.NET 10（C#）
- 型態：獨立 WebAPI 微服務（多租戶）
- 目標：
  - 提供「自家帳密驗證」與「外部 OpenID/OAuth 登入（Line/Microsoft/Google）」
  - 外部登入完成後，一律轉換為自家 JWT（Access/Refresh）
  - 租戶隔離：同一人於不同租戶視為不同身份、不同權限
  - 身分識別固定以 `(tenant_id, our_subject)` 二元組為唯一鍵

設計原則：

- Clean Architecture：抽象與共用模型放在 `Security.Abstractions`，核心授權邏輯放在 `Security.Authorization`，WebAPI host 與整合放在 `Security.Authentication`。
- 不存在 GlobalUsers：所有帳號、外部身份、權限均必須 tenant-scoped。
- OIDC/OAuth 必須做 mapping：`ExternalIdentity(tenant_id, provider, issuer, provider_sub) -> (tenant_id, our_subject)`。
- 不提供「外部帳號綁定/合併」：同一 tenant 內不允許多個外部 provider 綁定同一 `our_subject`。

---

## 2. Solution / 專案結構

- `Security.sln`
  - `Security.Abstractions`（class lib, net10.0）
    - 型別：`TenantId`、`OurSubject`、Claim 常數、DTO/介面
  - `Security.Authorization`（class lib, net10.0）
    - 角色/權限模型、授權判斷服務（permission/role check）
  - `Security.Authentication`（ASP.NET Core WebAPI, net10.0）
    - 帳密登入、OIDC/OAuth 入口與 callback、JWT/Refresh 發行、撤銷與 token-version

文件：`Security\\docs`

---

## 3. 核心識別模型（必守規則）

### 3.1 身分主鍵

- **SubjectKey**：`(tenant_id, our_subject)`
- `our_subject` 僅需在該 tenant 內唯一（例如 GUID/ULID/隨機字串皆可）。

本專案約定：

- `tenant_id` 使用 **GUID**。

### 3.2 不存在 GlobalUsers

- 不允許以 email/手機/外部 sub 當作跨 tenant 的全域識別。
- 同一自然人於 S1 與 S2 必須是兩個獨立 subject。

---

## 4. 外部登入 mapping（OIDC/OAuth）

### 4.1 ExternalIdentity 映射

- 表意：外部 provider 的身份只能在某一 tenant 下被辨識並對應到本系統 subject。
- Mapping：
  - `ExternalIdentity(tenant_id, provider, issuer, provider_sub) -> our_subject`

約束（必須落在資料庫唯一性/交易一致性）：

- `(tenant_id, provider, issuer, provider_sub)` 必須唯一。
- 同一 tenant 內 **禁止** 多 provider 指向同一 `our_subject`：
  - 建議加唯一約束 `(tenant_id, our_subject)` 於 ExternalIdentity 表（使每個 subject 最多只有一筆 external identity）。

### 4.2 首次 OIDC 登入的註冊行為

- 若 callback 後查無 `ExternalIdentity`：
  1. 建立新的 subject（生成 `our_subject`）
  2. 建立 `ExternalIdentity` 對應
  3. 建立 `Subject` 基本資料（可選：建立預設角色/權限）

---

## 5. Tenant-aware OIDC state（一次性，5 分鐘）

需求：tenant 必須能在 redirect 前產生 state（一次性、5 分鐘有效且需儲存），callback 透過 state 判斷屬於哪一個 tenant。

建議流程：

1. Client/Browser 呼叫 `GET /api/v1/auth/oidc/{provider}/challenge`（Header 帶 `X-Tenant-Id`）
2. API 建立一次性 state（5 分鐘），並將 `tenant_id + provider + PKCE(code_verifier) + nonce` 綁定到 state，然後 302 Redirect 到 provider
3. Provider 驗證完成回呼 `GET /api/v1/auth/oidc/{provider}/callback?state=...&code=...`
4. API Consume state（一次性）後完成 mapping 並簽發 tokens

state 儲存要求：

- `state` 必須不可預測（>= 128-bit 隨機）
- `expires_at = now + 5m`
- `used_at` 或 `consumed` 欄位確保一次性
- 必須綁定下列欄位（callback 需完整比對）：
  - `tenant_id`
  - `provider`
  - `nonce`
  - `code_verifier`（PKCE）

callback 驗證要求（安全負向案例）：

- state 存在但 provider 不符：回 `400 invalid_state`
- state 存在但 tenant 不符（若帶 `X-Tenant-Id` 且不符）：回 `400 invalid_state`（避免洩漏 state 所屬 tenant）
- nonce mismatch：回 `400 invalid_nonce`
- PKCE mismatch：回 `400 invalid_pkce`

一次性語意：

- callback 會先 consume state（atomic），因此「即使驗證失敗」也不允許重用同一 state（防止重放/暴力嘗試）。

清理：

- 提供 `CleanupExpiredStatesAsync(now)` method（可由 BackgroundService/排程呼叫）

---

## 6. Token 設計（Access/Refresh）

### 6.1 Access Token（短效）

- 建議存活：5 ~ 15 分鐘
- 必須包含 `tenant_id` claim
- 必須包含 `our_subject` claim

建議 claims：

- `iss` / `aud`
- `tenant_id`
- `sub`（建議放 our_subject，但必須搭配 tenant_id 才能形成 SubjectKey）
- `jti`
- `iat` / `exp`
- `tenant_tv`（tenant token version）
- `subject_tv`（subject token version）

### 6.2 Refresh Token（可撤銷）

- 只存 hash（不可明碼存 DB）
- 可撤銷：單顆撤銷、撤銷所有 subject 的 refresh、撤銷 tenant 全部 refresh
- 支援 rotation（refresh 時換發新 refresh，舊的標記 replaced/revoked）
- rotation 必須同交易（atomic）：避免併發 refresh 造成雙花；併發輸家可能回 `revoked_refresh_token`（單純失敗）或 `refresh_token_reuse_detected`（若讀到已 rotation 的舊 token，視策略可能終止 session）
- rotation 後舊 refresh token 再次被使用（`replaced_by` != null）視為可能被竊：回 `refresh_token_reuse_detected` 並終止 session（要求重新登入）

### 6.3 強制重新登入（tenant/user 等級）

最低可行策略（推薦）：

- DB 保存：
  - `Tenant.token_version`
  - `Subject.token_version`
- refresh 時驗證 token_version 是否匹配；不匹配則拒絕 refresh，要求重新登入
- access token 因短效自然收斂

進階（需要即時失效）：

- 以 denylist 對 `jti` 做黑名單（可用 Redis/MemoryCache），直到 token exp

---

## 7. 授權模型（Authorization）

授權判斷輸入：`(tenant_id, our_subject, permission)`。

建議資料模型（最小可行）：

- SubjectRole：subject 擁有哪些 role
- RolePermission：role 擁有哪些 permission
- （或簡化為 SubjectPermission 直接對 subject 授權）

JWT 是否內嵌 permission：

- 建議**不要**塞完整 permission 清單到 access token（會膨脹且變更難即時生效）。
- 最小做法：JWT 僅帶 subject key + 版本號；下游服務如需細緻授權，可呼叫本微服務做 permission check（或採用快取/同步）。

---

## 8. Entitlements（產品啟用）與授權判斷鏈

目標：在 RBAC 之前加上一層「產品啟用（entitlement）」門禁，使租戶可即時停用某產品而立即生效。

決策鏈（固定順序）：
1. JWT 驗證通過（含 tenant/user 狀態、session、token_version）
2. Entitlement 檢查：permission 對應的 product 在 tenant 下必須已啟用（含時間窗）
3. RBAC（roles / direct permissions / scopes）判斷 allow/deny

permission -> product 對應：
- 由 permission catalog 查出 `permissionKey -> productKey`（落地以 `permissions.product_key` 為來源）。
- 若 permissionKey 不存在：管理介面回 `404 not_found`；授權檢查則視既有設計回 deny。

---

## 9. Tenant / Platform 管理面（最小 API）

Tenant Admin（租戶管理者；需 `tenant_id` token）：
- `GET /api/v1/tenant/permissions?productKey=`：查詢 tenant 可用 permissions（僅已啟用 product）
- `POST /api/v1/tenant/users/{userId}/permissions`：新增直授 permission（先 entitlement gate）
- `DELETE /api/v1/tenant/users/{userId}/permissions/{permissionKey}`：移除直授 permission（先 entitlement gate）

Platform Admin（平台管理者；跨租戶）：
- `DELETE /api/v1/platform/tenants/{tenantId}/products/{productKey}`：移除 tenant_products（立即生效）

---

## 10. 風險與設計限制

### Permission Catalog 設計限制（本次僅文件說明；不調整行為）

- **Permissions 為平台統一（global）catalog**：permissions 表為全域共享，不是 tenant-scoped。
- **Permission Key 為全域唯一**：`permissionKey` 在整個平台必須唯一；不同租戶無法各自定義「同名但不同語意」的 permission key。
- **不支援租戶語意獨立的 permission key**：本次實作的 permissionKey -> productKey 對應與 entitlement 門禁，建立在「同一 permissionKey 對應同一 productKey」的前提。
- **若未來要支援 tenant-scoped permissions**：
  - 需要引入 tenant-scoped permission schema（例如 `(tenant_id, permission_key)` 或 tenant 專屬 catalog）。
  - 將影響 entitlement 與 RBAC 的資料模型與查詢邏輯（permission catalog、permission->productKey 對應、授權快取/失效策略等）。
  - **不在本次實作與修正範圍內**。

### 其他落地風險備忘

- **Grant 更新覆寫風險**：`SetSubjectGrantsAsync(...)` 為「全量取代」語意；因此 tenant permission 管理 API 必須先讀取並保留既有 roles/scopes，避免誤刪。
- **競態條件**：同一 subject 的權限變更若併發（多個管理者同時修改），可能發生最後寫入覆蓋；若要強化可考慮加上樂觀鎖（rowversion/updated_at）或在 store 層做 transactional compare-and-swap。
- **即時生效 vs 快取**：目前 entitlement 判斷以 DB 即時查詢，停用可立即生效；若未來加入快取，需明確 TTL/失效策略（並以 `authz_tenant_versions` 或事件通知做快取失效）。
- **時間窗一致性**：entitlement 依 `start_at/end_at` + `now` 判斷，需統一使用 UTC（`DateTimeOffset.UtcNow`）避免時區/DST 造成誤判。
- **權限命名與歸屬**：permissionKey 必須可一對一映射到 productKey；若允許 `product_key` 為 null 的 permission，需明確定義是否跳過 entitlement（建議管理 API 一律拒絕或僅允許平台級 permission）。

---

## 8. 邊界與後續釐清（需要你確認）

已確認：

- `tenant_id` 使用 GUID。
- 不需要 `app_id` / `client_id` 層級的隔離。
- OIDC Provider 設定採「全租戶共用同一組 clientId（各 provider 各自一組）」；但允許某 tenant **停用**特定 provider。

建議配置落點：

- `OidcProviderSettings`：全域 provider 設定（clientId/clientSecret、issuer、callback 等）。
- `TenantEnabledProviders`：逐租戶啟用清單（`tenant_id` + `provider`）。
