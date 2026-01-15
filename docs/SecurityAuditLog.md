# Security Audit Log（Append-only）

本文件定義 Security Audit Log 的資料落點、欄位規範、事件型別與敏感資料規則。

## 1. 落點與邊界

- Audit Log：寫入資料庫表 `security_audit_logs`（append-only）。
- Application/Error Log：只寫 JSON 檔案（Birdsoft.Infrastructure.Logging.Json），不得寫入 DB。

## 2. Append-only 規範

`security_audit_logs` 只允許 INSERT：
- 不允許 Update/Delete。
- Store/Repository 層只提供 `AppendAsync`/insert API。

Retention（清理）：
- 依 `occurred_at` 做時間窗清理（例：保留 180 天）。
- 清理 job 屬於 ops/host 責任；清理時不得破壞 tenant 隔離（永遠帶 `tenant_id`）。

## 3. 欄位規範（摘要）

建議每筆事件至少包含：
- `tenant_id`（必填）
- `our_subject`（依事件而定；匿名事件可空）
- `session_id`（若有）
- `type`（大分類，例如 `Auth` / `Token` / `Admin`）
- `code`（穩定事件鍵，見下）
- `occurred_at`（UTC）
- `success`（bool）
- `detail`（短字串；不得放敏感值）
- `data_json`（結構化 JSON；不得放敏感值）

## 4. 事件鍵（stable keys）

程式碼常數位於 `Security.Abstractions/Audit/SecurityAuditEventTypes.cs`。

- `Auth.Login.Success`
- `Auth.Login.Failed`
- `Auth.ExternalLogin.Success`
- `Auth.ExternalLogin.Failed`
- `Auth.Token.Issued`
- `Auth.Token.Refreshed`
- `Auth.Token.Revoked`
- `Auth.Subject.Locked`
- `Auth.Subject.Disabled`
- `Auth.Role.Assigned`
- `Auth.Role.Revoked`

> 事件 code 必須視為 API 合約：可以新增，不可修改既有語意。

## 5. 敏感資料規則（硬性禁止）

以下值不得寫入 `detail` 或 `data_json`：
- `password` / `password_hash`
- `access_token` / `refresh_token` / `id_token` 原文
- refresh token hash / access token hash
- 使用者 PII（email/phone）若有需求需遮罩或雜湊，並由產品/法務規範定義

錯誤堆疊/例外訊息：
- 僅允許寫入 JSON file log。
- Audit Log 可記錄 `error_code`（穩定碼）與有限度的原因描述，但不得帶 stack trace。
