//! OIDC 授权码流程编排（应用层）：授权决策、发码、令牌兑换、UserInfo。
//!
//! HTTP 细节（Cookie、表单、页面）在 `api::protocol`；这里只依赖数据库、配置与 key ring，
//! 返回"下一步做什么"，便于集成测试逐步断言。

use chrono::{DateTime, FixedOffset, Utc};
use sea_orm::{DatabaseConnection, EntityTrait};
use serde::Serialize;
use uuid::Uuid;

use crate::api::AppError;
use crate::entity::sea_orm_active_enums::{OidcClientStatus, OidcClientType};
use crate::entity::{oidc_auth_transactions, oidc_browser_sessions, oidc_clients, users};

use super::OidcProvider;
use super::clients;
use super::domain::authorize::{self, AuthorizationRequest, Prompt, RawParams};
use super::domain::claims::{self, IdTokenClaims, UserSnapshot};
use super::domain::client_auth::PresentedClientAuth;
use super::domain::error::OAuthError;
use super::domain::metadata::{PATH_CONSENT, PATH_LOGIN};
use super::domain::{pkce, redirect_uri, scope, secret};
use super::store;

/// 授权端点/页面处理后的下一步。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// 302 到已验证的 RP 回调（成功或标准错误）。
    RedirectToClient(String),
    /// 302 到本 OP 的登录/同意页。
    RedirectLocal(String),
    /// 渲染 FloatCTF 错误页（**不重定向**：client/redirect_uri 未验证或事务失效）。
    ErrorPage { status: u16, message: String },
}

impl Next {
    fn error_page(status: u16, message: impl Into<String>) -> Self {
        Self::ErrorPage {
            status,
            message: message.into(),
        }
    }
}

/// 当前浏览器带来的 SSO 会话（若有效）。
pub type SessionUser = (oidc_browser_sessions::Model, users::Model);

pub const TXN_EXPIRED_MESSAGE: &str =
    "授权请求已过期或无效（可能已完成、已超时，或不是在本浏览器中发起）。请返回应用重新登录。";

/// 带 `iss`（RFC 9207）的授权响应重定向。
fn client_redirect(oidc: &OidcProvider, redirect: &str, params: &[(&str, &str)]) -> String {
    let mut all: Vec<(&str, &str)> = params.to_vec();
    all.push(("iss", oidc.issuer()));
    redirect_uri::append_query(redirect, &all)
}

fn error_redirect(
    oidc: &OidcProvider,
    redirect: &str,
    err: &OAuthError,
    state: Option<&str>,
) -> Next {
    let mut params = vec![
        ("error", err.error),
        ("error_description", err.description.as_str()),
    ];
    if let Some(state) = state {
        params.push(("state", state));
    }
    Next::RedirectToClient(client_redirect(oidc, redirect, &params))
}

/// `GET|POST /oauth/authorize`：校验请求并创建授权事务，然后推进。
pub async fn start(
    db: &DatabaseConnection,
    oidc: &OidcProvider,
    params: &RawParams,
    browser_binding: &str,
    session: Option<SessionUser>,
) -> Result<Next, AppError> {
    let (client_id, redirect) = match authorize::client_and_redirect(params) {
        Ok(v) => v,
        Err(e) => return Ok(Next::error_page(400, e.message())),
    };
    let client = match clients::find_by_client_id(db, &client_id).await? {
        Some(c) if c.status == OidcClientStatus::Active => c,
        Some(_) => {
            return Ok(Next::error_page(
                400,
                "该应用当前未启用（待审批、已暂停或已被封禁）。",
            ));
        }
        None => return Ok(Next::error_page(400, "应用不存在（client_id 无效）。")),
    };
    if !redirect_uri::is_registered(&clients::redirect_uris_of(&client), &redirect) {
        return Ok(Next::error_page(
            400,
            "回调地址（redirect_uri）与该应用登记的地址不一致。",
        ));
    }

    // 从这里开始回调已验证，错误按规范回传给 RP。
    let state = params.echo_state();
    let policy = authorize::ClientPolicy {
        allowed_scopes: clients::scopes_of(&client),
        require_pkce: client.require_pkce || client.client_type == OidcClientType::Public,
    };
    let request = match authorize::validate(params, &client_id, &redirect, &policy) {
        Ok(r) => r,
        Err(e) => return Ok(error_redirect(oidc, &redirect, &e, state.as_deref())),
    };
    let hint_sub = match &request.id_token_hint {
        None => None,
        Some(hint) => match oidc.keys.verify::<IdTokenClaims>(hint, oidc.issuer(), true) {
            Ok(c) => Some(c.sub),
            Err(_) => {
                return Ok(error_redirect(
                    oidc,
                    &redirect,
                    &OAuthError::invalid_request("invalid id_token_hint"),
                    request.state.as_deref(),
                ));
            }
        },
    };
    let txn = store::create_transaction(
        db,
        &client,
        &request,
        hint_sub,
        browser_binding,
        oidc.config.transaction_ttl_secs,
    )
    .await?;
    advance(db, oidc, txn, &client, session).await
}

fn txn_prompt(txn: &oidc_auth_transactions::Model) -> Prompt {
    Prompt::from_values(&scope::from_json(&txn.prompt))
}

fn ts(t: &DateTime<FixedOffset>) -> i64 {
    t.timestamp()
}

/// 判断事务下一步：登录 → 同意 → 发码。`prompt=none` 时不展示任何页面。
pub async fn advance(
    db: &DatabaseConnection,
    oidc: &OidcProvider,
    txn: oidc_auth_transactions::Model,
    client: &oidc_clients::Model,
    session: Option<SessionUser>,
) -> Result<Next, AppError> {
    let prompt = txn_prompt(&txn);
    let now = Utc::now().timestamp();

    // id_token_hint 指向别的用户 → 当前会话不可用。
    let session = session.filter(|(_, user)| {
        txn.id_token_hint_sub
            .as_deref()
            .is_none_or(|sub| sub == user.id.to_string())
    });
    let needs_login = match &session {
        None => true,
        Some((s, _)) => {
            // 本事务内已重新输入过密码（且就是当前会话）即满足 prompt=login / max_age。
            let fresh_in_txn = txn.authenticated_at.is_some() && txn.session_id == Some(s.id);
            !fresh_in_txn
                && authorize::requires_fresh_login(
                    &prompt,
                    txn.max_age.map(i64::from),
                    ts(&s.auth_time),
                    now,
                )
        }
    };
    if needs_login {
        if prompt.none {
            return finish_with_error(db, oidc, &txn, OAuthError::login_required("login required"))
                .await;
        }
        return Ok(Next::RedirectLocal(format!("{PATH_LOGIN}?txn={}", txn.id)));
    }
    let (session, user) = session.expect("checked above");

    let requested = scope::from_json(&txn.scopes);
    let consent = store::find_active_consent(db, user.id, client.id).await?;
    let consented = consent
        .as_ref()
        .is_some_and(|c| scope::covers(&scope::from_json(&c.scopes), &requested));
    let needs_interaction = prompt.consent || prompt.select_account || !consented;

    let txn = if txn.user_id != Some(user.id) || txn.session_id != Some(session.id) {
        let fresh = txn.authenticated_at.is_some() && txn.session_id == Some(session.id);
        store::bind_transaction_user(db, txn, user.id, session.id, fresh).await?
    } else {
        txn
    };

    if needs_interaction {
        if prompt.none {
            return finish_with_error(
                db,
                oidc,
                &txn,
                OAuthError::consent_required("consent required"),
            )
            .await;
        }
        return Ok(Next::RedirectLocal(format!(
            "{PATH_CONSENT}?txn={}",
            txn.id
        )));
    }

    // 已有授权覆盖本次 scope：直接发码（只发本次申请的 scope）。
    issue_code(db, oidc, &txn, client, &session, &user, &requested).await
}

/// 结束事务并把错误带回 RP。
pub async fn finish_with_error(
    db: &DatabaseConnection,
    oidc: &OidcProvider,
    txn: &oidc_auth_transactions::Model,
    err: OAuthError,
) -> Result<Next, AppError> {
    if !store::complete_transaction(db, txn.id).await? {
        return Ok(Next::error_page(400, TXN_EXPIRED_MESSAGE));
    }
    Ok(error_redirect(
        oidc,
        &txn.redirect_uri,
        &err,
        txn.state.as_deref(),
    ))
}

/// 发码并结束事务。事务只能完成一次（双击/重放返回错误页）。
pub async fn issue_code(
    db: &DatabaseConnection,
    oidc: &OidcProvider,
    txn: &oidc_auth_transactions::Model,
    client: &oidc_clients::Model,
    session: &oidc_browser_sessions::Model,
    user: &users::Model,
    granted: &[String],
) -> Result<Next, AppError> {
    if !store::complete_transaction(db, txn.id).await? {
        return Ok(Next::error_page(400, TXN_EXPIRED_MESSAGE));
    }
    let code = store::insert_code(
        db,
        store::NewCode {
            client_pk: client.id,
            user_id: user.id,
            session_id: Some(session.id),
            redirect_uri: &txn.redirect_uri,
            scopes: granted,
            nonce: txn.nonce.clone(),
            code_challenge: txn.code_challenge.clone(),
            auth_time: session.auth_time,
            ttl_secs: oidc.config.authorization_code_ttl_secs,
        },
    )
    .await?;
    store::touch_session(db, session.id).await?;
    let mut params = vec![("code", code.as_str())];
    if let Some(state) = txn.state.as_deref() {
        params.push(("state", state));
    }
    Ok(Next::RedirectToClient(client_redirect(
        oidc,
        &txn.redirect_uri,
        &params,
    )))
}

/// 用户在同意页的选择 → 实际授予的 scope：`openid` 必含，其余取"本次申请 ∩ 勾选"。
pub fn granted_from_selection(requested: &[String], selected: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|s| s.as_str() == scope::OPENID || selected.contains(s))
        .cloned()
        .collect()
}

// ── Token 端点 ──────────────────────────────────────────────────────────────

/// Token 端点成功响应（RFC 6749 §5.1 + OIDC Core §3.1.3.3）。
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub id_token: String,
    pub scope: String,
}

/// Token 端点失败：错误 + 是否使用了 Basic（决定 `WWW-Authenticate`）。
#[derive(Debug)]
pub struct TokenFailure {
    pub error: OAuthError,
    pub status: u16,
}

impl TokenFailure {
    fn new(error: OAuthError) -> Self {
        let status = if error.error == "invalid_client" {
            401
        } else {
            400
        };
        Self { error, status }
    }
}

impl From<OAuthError> for TokenFailure {
    fn from(error: OAuthError) -> Self {
        Self::new(error)
    }
}

/// 客户端认证：认证方式必须与登记一致；机密客户端校验 secret（含轮换宽限期）。
pub async fn authenticate_client(
    db: &DatabaseConnection,
    presented: &PresentedClientAuth,
) -> Result<oidc_clients::Model, TokenFailure> {
    let invalid = || TokenFailure::new(OAuthError::invalid_client("client authentication failed"));
    let client = clients::find_by_client_id(db, presented.client_id())
        .await
        .map_err(|_| TokenFailure {
            error: OAuthError::server_error("temporarily unavailable"),
            status: 500,
        })?
        .ok_or_else(invalid)?;
    if client.status != OidcClientStatus::Active {
        return Err(invalid());
    }
    let registered = match client.token_endpoint_auth_method {
        crate::entity::sea_orm_active_enums::OidcTokenAuthMethod::ClientSecretBasic => {
            "client_secret_basic"
        }
        crate::entity::sea_orm_active_enums::OidcTokenAuthMethod::ClientSecretPost => {
            "client_secret_post"
        }
        crate::entity::sea_orm_active_enums::OidcTokenAuthMethod::None => "none",
    };
    if presented.method() != registered {
        return Err(invalid());
    }
    match presented {
        PresentedClientAuth::Basic { secret, .. } | PresentedClientAuth::Post { secret, .. } => {
            if !clients::verify_secret(&client, secret) {
                return Err(invalid());
            }
        }
        PresentedClientAuth::None { .. } => {
            if client.client_type != OidcClientType::Public {
                return Err(invalid());
            }
        }
    }
    Ok(client)
}

/// `grant_type=authorization_code` 兑换。客户端已通过认证。
pub async fn exchange_code(
    db: &DatabaseConnection,
    oidc: &OidcProvider,
    client: &oidc_clients::Model,
    params: &RawParams,
) -> Result<TokenResponse, TokenFailure> {
    let single = |name: &str| {
        params.single(name).map_err(|_| {
            TokenFailure::new(OAuthError::invalid_request(format!(
                "duplicate parameter: {name}"
            )))
        })
    };
    match single("grant_type")? {
        None => return Err(OAuthError::invalid_request("missing grant_type").into()),
        Some("authorization_code") => {}
        Some(_) => {
            return Err(
                OAuthError::unsupported_grant_type("only authorization_code is supported").into(),
            );
        }
    }
    let code_value = single("code")?
        .ok_or_else(|| TokenFailure::new(OAuthError::invalid_request("missing code")))?;
    let redirect = single("redirect_uri")?;
    let verifier = single("code_verifier")?;
    let invalid_grant =
        || TokenFailure::new(OAuthError::invalid_grant("invalid authorization code"));
    let db_error = |_| TokenFailure {
        error: OAuthError::server_error("temporarily unavailable"),
        status: 500,
    };

    let code = store::find_code(db, code_value)
        .await
        .map_err(db_error)?
        .ok_or_else(invalid_grant)?;
    // 绑定校验先于消费：错误的 client 拿到被盗的 code 也无法让合法 client 的兑换失败。
    if code.oidc_client_id != client.id {
        return Err(invalid_grant());
    }
    if code.consumed_at.is_some() {
        // 重放：撤销该授权码已签发的令牌（RFC 6749 §4.1.2 / RFC 9700 §4.5.3.1）。
        let revoked = store::revoke_tokens_of_code(db, code.id)
            .await
            .map_err(db_error)?;
        tracing::warn!(client_id = %client.client_id, revoked, "OIDC authorization code replay detected");
        return Err(invalid_grant());
    }
    if code.expires_at.with_timezone(&Utc) <= Utc::now() {
        return Err(invalid_grant());
    }
    match redirect {
        None => return Err(OAuthError::invalid_request("missing redirect_uri").into()),
        Some(r) if r != code.redirect_uri => return Err(invalid_grant()),
        Some(_) => {}
    }
    match (&code.code_challenge, verifier) {
        (Some(challenge), Some(v)) => {
            if !pkce::verify_s256(v, challenge) {
                return Err(TokenFailure::new(OAuthError::invalid_grant(
                    "PKCE verification failed",
                )));
            }
        }
        (Some(_), None) => {
            return Err(TokenFailure::new(OAuthError::invalid_grant(
                "code_verifier required",
            )));
        }
        // 防 PKCE 降级：发码时没有 challenge，兑换时却带 verifier → 拒绝（RFC 9700 §2.1.1）。
        (None, Some(_)) => {
            return Err(TokenFailure::new(OAuthError::invalid_grant(
                "code_verifier sent but no code_challenge was used",
            )));
        }
        (None, None) => {}
    }
    let user = users::Entity::find_by_id(code.user_id)
        .one(db)
        .await
        .map_err(|e| db_error(AppError::from(e)))?
        .ok_or_else(invalid_grant)?;
    let consent = store::find_active_consent(db, user.id, client.id)
        .await
        .map_err(db_error)?;
    let granted = scope::from_json(&code.scopes);
    if !consent.is_some_and(|c| scope::covers(&scope::from_json(&c.scopes), &granted)) {
        return Err(invalid_grant());
    }

    let Some((access_token, _)) =
        store::consume_code_and_issue_token(db, &code, oidc.config.access_token_ttl_secs)
            .await
            .map_err(db_error)?
    else {
        // 并发兑换中落败 / 恰好过期：按重放处理。
        let _ = store::revoke_tokens_of_code(db, code.id).await;
        return Err(invalid_grant());
    };

    let now = Utc::now().timestamp();
    let id_claims = IdTokenClaims {
        iss: oidc.issuer().to_string(),
        sub: user.id.to_string(),
        aud: client.client_id.clone(),
        azp: client.client_id.clone(),
        exp: now + oidc.config.id_token_ttl_secs,
        iat: now,
        auth_time: code.auth_time.timestamp(),
        nonce: code.nonce.clone(),
        at_hash: Some(claims::at_hash(&access_token)),
    };
    let id_token = oidc.keys.sign(&id_claims).map_err(|e| {
        tracing::error!(error = %e, "OIDC id_token signing failed");
        TokenFailure {
            error: OAuthError::server_error("token signing unavailable"),
            status: 500,
        }
    })?;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: oidc.config.access_token_ttl_secs,
        id_token,
        scope: scope::join(&granted),
    })
}

pub fn snapshot(user: &users::Model) -> UserSnapshot {
    UserSnapshot {
        id: user.id,
        username: user.username.clone(),
        nickname: user.nickname.clone(),
        email: user.email.clone(),
        avatar: user.avatar.clone(),
        updated_at: user.updated_at.timestamp(),
    }
}

/// UserInfo：返回 `None` 表示令牌不可用（401 invalid_token）。
pub async fn userinfo(
    db: &DatabaseConnection,
    oidc: &OidcProvider,
    access_token: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AppError> {
    let Some(ctx) = store::find_usable_token(db, access_token).await? else {
        return Ok(None);
    };
    let scopes = scope::from_json(&ctx.token.scopes);
    Ok(Some(claims::userinfo(
        &snapshot(&ctx.user),
        &scopes,
        oidc.issuer(),
    )))
}

/// 由 SSO Cookie 解析当前会话。
pub async fn current_session(
    db: &DatabaseConnection,
    cookie_value: Option<&str>,
) -> Result<Option<SessionUser>, AppError> {
    match cookie_value {
        Some(v) => store::find_valid_session(db, v).await,
        None => Ok(None),
    }
}

/// 解析页面表单中的事务 id。
pub fn parse_txn_id(raw: Option<&str>) -> Option<Uuid> {
    raw.and_then(|v| Uuid::parse_str(v).ok())
}

/// 便于测试的类型别名：授权请求校验结果。
pub type ValidatedRequest = AuthorizationRequest;

/// 生成新的浏览器绑定值。
pub fn new_browser_binding() -> String {
    secret::new_opaque_secret()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn consent_selection_keeps_openid_and_never_adds_unrequested() {
        let requested = s(&["openid", "profile", "email"]);
        assert_eq!(granted_from_selection(&requested, &[]), s(&["openid"]));
        assert_eq!(
            granted_from_selection(&requested, &s(&["email"])),
            s(&["openid", "email"])
        );
        // 勾选未申请的 scope 不会被授予
        assert_eq!(
            granted_from_selection(&s(&["openid"]), &s(&["profile", "email"])),
            s(&["openid"])
        );
    }
}
