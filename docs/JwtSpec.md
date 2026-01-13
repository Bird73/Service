# JWT Spec（契約）

本文件描述本模組簽發之 Access Token（JWT）最小契約與 claim 對齊規則。

## 必要 claims

Access Token 必須至少包含：

- `iss`：必須完全匹配設定的 `JwtOptions.Issuer`
- `aud`：必須包含設定的 `JwtOptions.Audience`
- `exp`：過期時間
- `iat`：簽發時間
- `nbf`：最早可用時間
- `jti`：JWT ID（可用於 denylist / 即時撤銷）
- `sub`：本系統 subject（語意上等同 `our_subject`）
- `tenant_id`：租戶 GUID
- `session_id`：可撤銷 session id（GUID；用於即時撤銷/登出）

對應 code 常數：`Security.Abstractions.Constants.SecurityJwtSpec`、`Security.Abstractions.Constants.SecurityClaimTypes`。

## 角色 / 權限 claims

- 角色（**canonical**）：`roles`（JWT array / 多值 claim；每個值為 string）
	- 相容：可同時接受 `role` 單值或多值 claim
- 範圍（**canonical**）：`scopes`（JWT array / 多值 claim；每個值為 string）
	- 相容：可同時輸出/接受 `scope`（space-delimited string）
- 權限（可選，但若使用則需一致）：`permissions`（JWT array / 多值 claim；每個值為 string）

## 其他建議 claims

- `our_subject`：可選（若輸出，值應與 `sub` 相同）
- `provider` / `issuer` / `external_sub`：可選（除錯與稽核用途；勿作為授權信任來源）

## 驗證規則摘要

- `iss` 必須符合設定
- `aud` 必須包含設定 audience
- `exp/iat/nbf` 必須落在允許的時間窗（由 `JwtOptions.ClockSkewSeconds` 控制）
- `kid`（JWT header）必須存在：驗證端依 `kid` 選擇 signing key；缺失或未知視為 `invalid_token`
- key rotation：新舊 key 共存期間，舊 token 必須仍可驗證；移除舊 key 後，舊 token 必須不可驗證
- 若採即時撤銷：驗證端必須檢查 `jti` 是否在 denylist 或版本號是否匹配
- 若 token 包含 `session_id`：驗證端應檢查 session 是否仍為 active（否則視為 `session_terminated`）
