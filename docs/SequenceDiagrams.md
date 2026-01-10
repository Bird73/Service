# Company.Security 循序圖

> 以 Mermaid 格式繪製主要驗證/授權流程。

---

## 1. Password Login（自家帳密登入）

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Authentication API
    participant AS as IAuthenticationService
    participant LA as ILocalAccountRepository
    participant TS as ITokenService
    participant DB as Database

    C->>API: POST /api/auth/password/login<br/>{tenant_id, username, password}
    API->>AS: AuthenticateByPasswordAsync(tenant_id, username, password)
    AS->>LA: FindByUsernameAsync(tenant_id, username)
    LA->>DB: SELECT LocalAccount
    DB-->>LA: LocalAccount | null
    LA-->>AS: LocalAccount | null

    alt Account not found
        AS-->>API: AuthResult.Fail("InvalidCredentials")
        API-->>C: 401 Unauthorized
    else Account found
        AS->>AS: VerifyPasswordHash(password, account.PasswordHash)
        alt Password mismatch
            AS-->>API: AuthResult.Fail("InvalidCredentials")
            API-->>C: 401 Unauthorized
        else Password valid
            AS->>TS: GenerateTokensAsync(tenant_id, our_subject)
            TS->>DB: INSERT RefreshToken (hash)
            TS-->>AS: TokenPair {access_token, refresh_token, expires_in}
            AS-->>API: AuthResult.Success(TokenPair)
            API-->>C: 200 OK {access_token, refresh_token, expires_in}
        end
    end
```

---

## 2. OIDC Login（外部登入 - 含 State 建立與 Callback）

### 2.1 建立 State

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Authentication API
    participant SS as IAuthStateService
    participant DB as Database

    C->>API: POST /api/tenants/{tenantId}/auth/state
    API->>SS: CreateStateAsync(tenant_id)
    SS->>SS: Generate random state (>=128-bit)
    SS->>DB: INSERT AuthState (state, tenant_id, expires_at=now+5m)
    SS-->>API: {state, expires_at}
    API-->>C: 200 OK {state, expires_at}
```

### 2.2 啟動 OIDC Challenge

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Authentication API
    participant SS as IAuthStateService
    participant PS as IOidcProviderService
    participant DB as Database

    C->>API: GET /api/auth/oidc/{provider}/start?state=xxx
    API->>SS: ValidateAndGetTenantAsync(state)
    SS->>DB: SELECT AuthState WHERE state=xxx AND used_at IS NULL AND expires_at > now
    DB-->>SS: AuthState | null

    alt State invalid/expired
        SS-->>API: null
        API-->>C: 400 Bad Request (invalid_state)
    else State valid
        SS-->>API: tenant_id
        API->>PS: IsTenantProviderEnabledAsync(tenant_id, provider)
        PS->>DB: SELECT TenantEnabledProviders
        DB-->>PS: enabled | not found

        alt Provider not enabled for tenant
            PS-->>API: false
            API-->>C: 403 Forbidden (provider_not_enabled)
        else Provider enabled
            PS-->>API: true
            API->>PS: GetAuthorizationUrl(provider, state)
            PS-->>API: authorization_url
            API-->>C: 302 Redirect to authorization_url
        end
    end
```

### 2.3 OIDC Callback（首次登入自動註冊）

```mermaid
sequenceDiagram
    participant P as OIDC Provider
    participant API as Authentication API
    participant SS as IAuthStateService
    participant PS as IOidcProviderService
    participant ES as IExternalIdentityService
    participant TS as ITokenService
    participant DB as Database

    P->>API: GET /api/auth/oidc/{provider}/callback?state=xxx&code=yyy
    API->>SS: ConsumeStateAsync(state)
    SS->>DB: UPDATE AuthState SET used_at=now WHERE state=xxx AND used_at IS NULL
    DB-->>SS: affected rows

    alt State already used or not found
        SS-->>API: null
        API-->>P: 400 Bad Request (invalid_state)
    else State consumed
        SS-->>API: tenant_id
        API->>PS: ExchangeCodeAsync(provider, code)
        PS->>P: POST /token {code, client_id, client_secret}
        P-->>PS: {id_token, access_token}
        PS->>PS: Validate id_token, extract (issuer, provider_sub)
        PS-->>API: OidcUserInfo {issuer, provider_sub, email?, name?}

        API->>ES: FindOrCreateSubjectAsync(tenant_id, provider, issuer, provider_sub)
        ES->>DB: SELECT ExternalIdentity WHERE (tenant_id, provider, issuer, provider_sub)
        DB-->>ES: ExternalIdentity | null

        alt ExternalIdentity exists
            ES-->>API: our_subject
        else First login - auto register
            ES->>ES: Generate new our_subject (GUID)
            ES->>DB: BEGIN TRANSACTION
            ES->>DB: INSERT Subject (tenant_id, our_subject)
            ES->>DB: INSERT ExternalIdentity (tenant_id, provider, issuer, provider_sub, our_subject)
            ES->>DB: COMMIT
            ES-->>API: our_subject
        end

        API->>TS: GenerateTokensAsync(tenant_id, our_subject)
        TS->>DB: INSERT RefreshToken (hash)
        TS-->>API: TokenPair
        API-->>P: 200 OK {access_token, refresh_token, expires_in}
    end
```

---

## 3. Token Refresh

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Authentication API
    participant TS as ITokenService
    participant DB as Database

    C->>API: POST /api/auth/token/refresh<br/>{refresh_token}
    API->>TS: RefreshAsync(refresh_token)
    TS->>TS: Hash(refresh_token)
    TS->>DB: SELECT RefreshToken WHERE token_hash=xxx AND revoked_at IS NULL AND expires_at > now
    DB-->>TS: RefreshToken | null

    alt Token not found or revoked
        TS-->>API: RefreshResult.Fail("invalid_token")
        API-->>C: 401 Unauthorized
    else Token valid
        TS->>DB: SELECT Tenant.token_version, Subject.token_version
        DB-->>TS: tenant_tv, subject_tv

        alt Token version mismatch (force re-login)
            TS->>DB: UPDATE RefreshToken SET revoked_at=now
            TS-->>API: RefreshResult.Fail("token_version_mismatch")
            API-->>C: 401 Unauthorized (re-login required)
        else Version OK - Rotate token
            TS->>DB: UPDATE RefreshToken SET revoked_at=now, replaced_by=new_id
            TS->>DB: INSERT RefreshToken (new hash, new expires_at)
            TS->>TS: GenerateAccessToken(tenant_id, our_subject, tenant_tv, subject_tv)
            TS-->>API: TokenPair {new access_token, new refresh_token}
            API-->>C: 200 OK {access_token, refresh_token, expires_in}
        end
    end
```

---

## 4. Token Revoke

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Authentication API
    participant TS as ITokenService
    participant DB as Database

    C->>API: POST /api/auth/token/revoke<br/>{refresh_token}
    API->>TS: RevokeAsync(refresh_token)
    TS->>TS: Hash(refresh_token)
    TS->>DB: UPDATE RefreshToken SET revoked_at=now WHERE token_hash=xxx
    DB-->>TS: affected rows
    TS-->>API: RevokeResult.Success
    API-->>C: 200 OK
```

---

## 5. Force Re-login（Bump Token Version）

### 5.1 Tenant 級別

```mermaid
sequenceDiagram
    participant Admin as Admin Client
    participant API as Authentication API
    participant TS as ITenantService
    participant DB as Database

    Admin->>API: POST /api/tenants/{tenantId}/token-version/bump
    API->>TS: BumpTenantTokenVersionAsync(tenant_id)
    TS->>DB: UPDATE Tenants SET token_version = token_version + 1 WHERE tenant_id=xxx
    DB-->>TS: affected rows
    TS-->>API: new token_version
    API-->>Admin: 200 OK {new_token_version}
```

### 5.2 Subject 級別

```mermaid
sequenceDiagram
    participant Admin as Admin Client
    participant API as Authentication API
    participant SS as ISubjectService
    participant DB as Database

    Admin->>API: POST /api/tenants/{tenantId}/subjects/{ourSubject}/token-version/bump
    API->>SS: BumpSubjectTokenVersionAsync(tenant_id, our_subject)
    SS->>DB: UPDATE Subjects SET token_version = token_version + 1 WHERE (tenant_id, our_subject)
    DB-->>SS: affected rows
    SS-->>API: new token_version
    API-->>Admin: 200 OK {new_token_version}
```

---

## 6. Authorization Check

```mermaid
sequenceDiagram
    participant C as Client / Resource Server
    participant API as Authentication API
    participant AZ as IAuthorizationService
    participant DB as Database

    C->>API: POST /api/authz/check<br/>{tenant_id, our_subject, permission}
    API->>AZ: CheckPermissionAsync(tenant_id, our_subject, permission)
    AZ->>DB: SELECT FROM SubjectRoles sr<br/>JOIN RolePermissions rp ON sr.role_id = rp.role_id<br/>WHERE sr.tenant_id=? AND sr.our_subject=? AND rp.permission=?
    DB-->>AZ: rows

    alt Permission granted
        AZ-->>API: AuthzResult {allowed: true}
        API-->>C: 200 OK {allowed: true}
    else Permission denied
        AZ-->>API: AuthzResult {allowed: false}
        API-->>C: 200 OK {allowed: false}
    end
```

---

## 7. Cleanup Expired States

```mermaid
sequenceDiagram
    participant BG as Background Service / Scheduler
    participant SS as IAuthStateService
    participant DB as Database

    BG->>SS: CleanupExpiredStatesAsync(now)
    SS->>DB: DELETE FROM AuthStates WHERE expires_at < now OR used_at IS NOT NULL
    DB-->>SS: deleted count
    SS-->>BG: deleted count
```
