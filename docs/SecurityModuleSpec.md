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
2. API 建立一次性 state（5 分鐘），綁定 PKCE/nonce，並 302 Redirect 到 provider
3. Provider 驗證完成回呼 `GET /api/v1/auth/oidc/{provider}/callback?state=...&code=...`
4. API Consume state（一次性）後完成 mapping 並簽發 tokens

state 儲存要求：

- `state` 必須不可預測（>= 128-bit 隨機）
- `expires_at = now + 5m`
- `used_at` 或 `consumed` 欄位確保一次性

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

## 8. 邊界與後續釐清（需要你確認）

已確認：

- `tenant_id` 使用 GUID。
- 不需要 `app_id` / `client_id` 層級的隔離。
- OIDC Provider 設定採「全租戶共用同一組 clientId（各 provider 各自一組）」；但允許某 tenant **停用**特定 provider。

建議配置落點：

- `OidcProviderSettings`：全域 provider 設定（clientId/clientSecret、issuer、callback 等）。
- `TenantEnabledProviders`：逐租戶啟用清單（`tenant_id` + `provider`）。
