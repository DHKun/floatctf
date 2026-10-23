# FloatCTF OpenID Connect Provider —— 参考手册

FloatCTF 可以作为通用 **OpenID Provider（OP）**：任何标准 OIDC 客户端只需
`issuer`、`client_id`、（机密客户端的）`client_secret` 与回调地址，就能让用户用 FloatCTF 账号登录。

- 设计决策：[ADR-oidc-provider.md](./ADR-oidc-provider.md)
- 第三方接入：[oidc-client-integration.md](./oidc-client-integration.md)
- 部署与运维：[oidc-operations.md](./oidc-operations.md)
- 测试证据：[oidc-test-report.md](./oidc-test-report.md)

> FloatCTF **没有** 取得 OpenID Foundation 官方认证。一致性测试的实际结果见测试报告。

## 1. 端点

所有地址都以 issuer（站点 origin，例如 `https://ctf.example.com`）为前缀。`[oidc].enabled = false` 时全部返回 404。

| 端点 | 方法 | 说明 |
|------|------|------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery（`Cache-Control: public, max-age=300`） |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 元数据（与上相同） |
| `/.well-known/jwks.json` | GET | 签名公钥（仅 `kty/n/e/kid/alg/use`） |
| `/oauth/authorize` | GET, POST | 授权端点 |
| `/oauth/token` | POST | Token 端点（`application/x-www-form-urlencoded`） |
| `/oauth/userinfo` | GET, POST | UserInfo（Bearer） |
| `/oauth/login`、`/oauth/consent` | GET, POST | 第一方登录 / 授权确认页（服务端渲染，RP 不直接调用） |
| `/oauth/logout` | POST | 只清除 FloatCTF 本地 SSO 会话（**不是** RP-Initiated Logout） |

平台内管理接口（需要 FloatCTF 平台 JWT，不属于 OIDC 协议面）：

| 接口 | 说明 |
|------|------|
| `POST /api/users/sso`、`DELETE /api/users/sso` | SPA 建立 / 撤销 SSO 会话 |
| `/api/oidc/provider`、`/api/oidc/clients[/{client_id}[/secret|/disable|/enable]]` | 开发者中心 |
| `/api/oidc/authorizations[/{client_id}]` | 用户已授权应用 |
| `/api/admin/oidc/clients[/{client_id}/approve|reject|suspend|reinstate|pkce]` | 管理员审核 |

## 2. 宣告的能力（Discovery 实际内容）

| 字段 | 值 |
|------|----|
| `response_types_supported` | `["code"]` |
| `response_modes_supported` | `["query"]` |
| `grant_types_supported` | `["authorization_code"]` |
| `subject_types_supported` | `["public"]` |
| `id_token_signing_alg_values_supported` | `["RS256"]` |
| `scopes_supported` | `["openid","profile","email"]` |
| `token_endpoint_auth_methods_supported` | `["client_secret_basic","client_secret_post","none"]` |
| `code_challenge_methods_supported` | `["S256"]` |
| `claims_parameter_supported` / `request_parameter_supported` / `request_uri_parameter_supported` | `false` |
| `authorization_response_iss_parameter_supported` | `true`（RFC 9207，防 mix-up） |

**未实现、未宣告**：Implicit / Hybrid、Refresh Token、Client Credentials、ROPC、Device Flow、动态注册（RFC 7591）、
Token Revocation / Introspection、RP-Initiated / Front- / Back-Channel Logout、pairwise subject、request object、PAR、mTLS、
`private_key_jwt` / `client_secret_jwt`。

## 3. 授权请求

| 参数 | 规则 |
|------|------|
| `client_id`、`redirect_uri` | 必填。应用必须处于「已启用」；`redirect_uri` 与登记值**逐字节相等**。任一不合法 → FloatCTF 错误页（**不重定向**） |
| `response_type` | 只能是 `code` |
| `scope` | 必须含 `openid`；未支持 / 未允许的 scope 被忽略（实际授予的 scope 见 token 响应 `scope`） |
| `state` | 推荐；原样回传（≤2048 字节） |
| `nonce` | 推荐；写入 ID Token（≤512 字节）。若管理员为某机密客户端豁免 PKCE，则 `nonce` **必填** |
| `code_challenge`、`code_challenge_method` | `S256`；公开客户端必填；机密客户端默认必填。`plain` 或缺省 method 一律拒绝 |
| `prompt` | `none` / `login` / `consent` / `select_account`；`none` 不能与其他值组合 |
| `max_age` | 非负整数；超过即要求重新输入密码，`0` 等同 `prompt=login` |
| `id_token_hint` | 本 OP 签发的 ID Token（可过期）；与当前会话用户不一致时要求重新登录 |
| `login_hint` | 仅用于预填用户名 |
| `request` / `request_uri` / `registration` | 返回 `request_not_supported` / `request_uri_not_supported` / `registration_not_supported` |

任何参数重复出现 → `invalid_request`。授权响应（成功或错误）都带 `iss`。

## 4. Token 端点

- `grant_type=authorization_code`，必须带与授权请求一致的 `redirect_uri`。
- 客户端认证方式必须与登记方式一致：`client_secret_basic`（Basic 中的 id/secret 先做 form-urlencode）、
  `client_secret_post`、`none`（公开客户端）。同时使用多种方式 → `invalid_request`。
- PKCE：授权时带了 challenge，兑换必须带正确的 `code_verifier`；授权时没带，兑换时带了 verifier 也拒绝（防降级）。
- 授权码：只存摘要、默认 60 秒（上限 120 秒）、一次性。重复兑换 → `invalid_grant`，并撤销该授权码已签发的 access token。
- 成功响应：

```json
{ "access_token": "fat_…", "token_type": "Bearer", "expires_in": 3600, "id_token": "eyJ…", "scope": "openid profile" }
```

所有响应带 `Cache-Control: no-store`、`Pragma: no-cache`。每个 client 每分钟最多 300 次请求。

## 5. ID Token

JWS RS256，header 含 `kid` 与 `typ=JWT`。Claims：

| Claim | 说明 |
|-------|------|
| `iss` | 与 Discovery `issuer` 逐字节一致 |
| `sub` | FloatCTF 用户 UUID（稳定、永不复用）。**以 `(iss, sub)` 作为用户唯一标识** |
| `aud`、`azp` | 你的 `client_id` |
| `exp`、`iat` | 默认有效期 1 小时 |
| `auth_time` | 用户实际输入密码的时间（始终提供） |
| `nonce` | 授权请求带了就原样返回 |
| `at_hash` | access token 的左半 SHA-256 |
| （无资料 claims） | `preferred_username`、`email` 等**只经 UserInfo 返回**（OIDC Core §5.4，最小披露）；需要资料请调用 UserInfo |

## 6. UserInfo 与 scope

| Scope | Claims |
|-------|--------|
| `openid` | `sub` |
| `profile` | `preferred_username`（用户名）、`nickname`、`name`（同昵称）、`picture`（有头像时，绝对 URL）、`updated_at` |
| `email` | `email`、`email_verified: false`（平台没有邮箱验证流程；邮箱为空时不返回） |

不返回：密码、角色、管理员身份、战队、赛事、成绩、IP 等任何业务数据。
UserInfo 支持 `Authorization: Bearer` 或 POST 表单 `access_token`（二选一）。
以下情况 access token 立即失效（401 `invalid_token`）：过期、用户撤销授权、应用被暂停 / 封禁 / 删除、授权码重放、用户被删除。

## 7. 错误

授权端点（重定向回 RP）：`invalid_request`、`unsupported_response_type`、`invalid_scope`、`access_denied`、
`login_required`、`consent_required`、`request_not_supported`、`request_uri_not_supported`、`registration_not_supported`。

Token 端点（JSON）：`invalid_request`（400）、`invalid_client`（401，Basic 时带 `WWW-Authenticate: Basic`）、
`invalid_grant`（400）、`unsupported_grant_type`（400）、`temporarily_unavailable`（429 限流 / 503 限流后端故障）。

UserInfo：401 + `WWW-Authenticate: Bearer error="invalid_token"`；无令牌时 401 且不带 error。

## 8. 会话与安全属性

- 用户在 FloatCTF 网页登录后（`POST /api/users/session`），浏览器获得 HttpOnly SSO Cookie（https 下 `__Host-fctf_sso`，
  `SameSite=Lax`，默认 8 小时）；授权第三方时无需再次输入密码。登出时服务端撤销该会话。
- 登录 / 同意表单：一次性 CSRF token + 浏览器绑定 Cookie + `Origin` 校验；授权事务 10 分钟有效且只能完成一次。
- 登录限流：每用户名 5 分钟 10 次、每 IP 50 次（设置表 `OIDC_LOGIN_RATE_PER_USER` / `OIDC_LOGIN_RATE_PER_IP` 可调）；
  Redis 不可用时拒绝登录（fail-closed）。
- 撤销授权或停用应用只影响 FloatCTF 侧令牌；**已签发的 ID Token 不能追溯撤回，RP 自己的登录会话也不会被退出**。

## 9. 已知限制

- 回环（loopback）回调需要运维开启 `allow_loopback_redirect_uris`，且端口必须与登记值完全一致（未实现 RFC 8252 的任意端口匹配）。
- 只支持根路径 issuer（不支持 `https://host/path` 形式）。
- 没有 Refresh Token：access token 过期后 RP 需重新走授权（有 SSO 时用户无感）。
- `email_verified` 恒为 `false`。
