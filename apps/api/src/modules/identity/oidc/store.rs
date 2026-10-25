//! OIDC 运行期状态的持久化：SSO 会话、授权事务、授权码、access token、用户授权。
//!
//! 所有令牌类值只以 SHA-256 摘要入库/查询；"一次性"语义一律用条件 UPDATE 实现，
//! 由数据库保证并发下只有一个请求成功。

use chrono::{DateTime, Duration, FixedOffset, Utc};
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, TransactionTrait,
    sea_query::{Expr, OnConflict},
};
use uuid::Uuid;

use crate::api::AppError;
use crate::entity::{
    oidc_access_tokens, oidc_auth_transactions, oidc_authorization_codes, oidc_browser_sessions,
    oidc_clients, oidc_consents, users,
};

use super::domain::{authorize::AuthorizationRequest, scope, secret};

fn now() -> DateTime<FixedOffset> {
    Utc::now().fixed_offset()
}

// ── SSO 会话 ────────────────────────────────────────────────────────────────

/// 会话建立方式（与表 CHECK 约束一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOrigin {
    PasswordLogin,
    OidcLogin,
    JwtBridge,
}

impl SessionOrigin {
    fn as_str(self) -> &'static str {
        match self {
            Self::PasswordLogin => "password_login",
            Self::OidcLogin => "oidc_login",
            Self::JwtBridge => "jwt_bridge",
        }
    }
}

/// 新建会话，返回 Cookie 明文与行。
pub async fn create_session(
    db: &DatabaseConnection,
    user_id: Uuid,
    auth_time: DateTime<FixedOffset>,
    ttl_secs: i64,
    origin: SessionOrigin,
) -> Result<(String, oidc_browser_sessions::Model), AppError> {
    let secret_value = secret::new_opaque_secret();
    let now = now();
    let model = oidc_browser_sessions::ActiveModel {
        id: Set(Uuid::new_v4()),
        session_hash: Set(secret::sha256_hex(&secret_value)),
        user_id: Set(user_id),
        auth_time: Set(auth_time),
        established_via: Set(origin.as_str().to_string()),
        created_at: Set(now),
        last_seen_at: Set(now),
        expires_at: Set(now + Duration::seconds(ttl_secs)),
        revoked_at: Set(None),
    }
    .insert(db)
    .await?;
    Ok((secret_value, model))
}

/// 由 Cookie 明文找有效会话（未过期、未撤销、用户仍存在）。
pub async fn find_valid_session(
    db: &DatabaseConnection,
    cookie_value: &str,
) -> Result<Option<(oidc_browser_sessions::Model, users::Model)>, AppError> {
    if !secret::is_plausible_token(cookie_value) {
        return Ok(None);
    }
    let found = oidc_browser_sessions::Entity::find()
        .filter(oidc_browser_sessions::Column::SessionHash.eq(secret::sha256_hex(cookie_value)))
        .filter(oidc_browser_sessions::Column::RevokedAt.is_null())
        .filter(oidc_browser_sessions::Column::ExpiresAt.gt(now()))
        .find_also_related(users::Entity)
        .one(db)
        .await?;
    Ok(match found {
        Some((session, Some(user))) => Some((session, user)),
        _ => None,
    })
}

pub async fn find_session_by_id(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<Option<oidc_browser_sessions::Model>, AppError> {
    Ok(oidc_browser_sessions::Entity::find_by_id(id)
        .filter(oidc_browser_sessions::Column::RevokedAt.is_null())
        .filter(oidc_browser_sessions::Column::ExpiresAt.gt(now()))
        .one(db)
        .await?)
}

pub async fn touch_session(db: &DatabaseConnection, id: Uuid) -> Result<(), AppError> {
    oidc_browser_sessions::Entity::update_many()
        .col_expr(
            oidc_browser_sessions::Column::LastSeenAt,
            Expr::value(now()),
        )
        .filter(oidc_browser_sessions::Column::Id.eq(id))
        .exec(db)
        .await?;
    Ok(())
}

/// 撤销 Cookie 对应的会话（幂等）。
pub async fn revoke_session(db: &DatabaseConnection, cookie_value: &str) -> Result<bool, AppError> {
    if !secret::is_plausible_token(cookie_value) {
        return Ok(false);
    }
    let res = oidc_browser_sessions::Entity::update_many()
        .col_expr(oidc_browser_sessions::Column::RevokedAt, Expr::value(now()))
        .filter(oidc_browser_sessions::Column::SessionHash.eq(secret::sha256_hex(cookie_value)))
        .filter(oidc_browser_sessions::Column::RevokedAt.is_null())
        .exec(db)
        .await?;
    Ok(res.rows_affected > 0)
}

// ── 授权事务 ────────────────────────────────────────────────────────────────

/// 新建授权事务，返回行。
pub async fn create_transaction(
    db: &DatabaseConnection,
    client: &oidc_clients::Model,
    request: &AuthorizationRequest,
    id_token_hint_sub: Option<String>,
    browser_binding: &str,
    ttl_secs: i64,
) -> Result<oidc_auth_transactions::Model, AppError> {
    let now = now();
    Ok(oidc_auth_transactions::ActiveModel {
        id: Set(Uuid::new_v4()),
        oidc_client_id: Set(client.id),
        browser_binding_hash: Set(secret::sha256_hex(browser_binding)),
        // 页面渲染时才生成真正的 CSRF token；初始值是不可猜测的占位摘要。
        csrf_hash: Set(secret::sha256_hex(&secret::new_opaque_secret())),
        redirect_uri: Set(request.redirect_uri.clone()),
        scopes: Set(scope::to_json(&request.scopes)),
        state: Set(request.state.clone()),
        nonce: Set(request.nonce.clone()),
        code_challenge: Set(request.code_challenge.clone()),
        code_challenge_method: Set(request
            .code_challenge
            .as_ref()
            .map(|_| super::domain::pkce::METHOD_S256.to_string())),
        prompt: Set(serde_json::Value::from(request.prompt.to_values())),
        max_age: Set(request.max_age.map(|v| v.min(i32::MAX as i64) as i32)),
        login_hint: Set(request.login_hint.clone()),
        id_token_hint_sub: Set(id_token_hint_sub),
        user_id: Set(None),
        session_id: Set(None),
        authenticated_at: Set(None),
        created_at: Set(now),
        expires_at: Set(now + Duration::seconds(ttl_secs)),
        completed_at: Set(None),
        account_choice_session_id: Set(None),
        account_selected_at: Set(None),
        account_selected_session_id: Set(None),
        account_switch_requested_at: Set(None),
    }
    .insert(db)
    .await?)
}

/// 找到仍可推进的事务：未过期、未完成、由同一浏览器发起，且应用仍为 active
/// （事务进行中被暂停/封禁的应用不能再推进登录、选择或同意）。
pub async fn find_live_transaction(
    db: &DatabaseConnection,
    id: Uuid,
    browser_binding: Option<&str>,
) -> Result<Option<(oidc_auth_transactions::Model, oidc_clients::Model)>, AppError> {
    let Some(binding) = browser_binding.filter(|b| secret::is_plausible_token(b)) else {
        return Ok(None);
    };
    let found = oidc_auth_transactions::Entity::find_by_id(id)
        .filter(oidc_auth_transactions::Column::CompletedAt.is_null())
        .filter(oidc_auth_transactions::Column::ExpiresAt.gt(now()))
        .filter(oidc_auth_transactions::Column::BrowserBindingHash.eq(secret::sha256_hex(binding)))
        .find_also_related(oidc_clients::Entity)
        .one(db)
        .await?;
    Ok(match found {
        Some((txn, Some(client)))
            if client.status == crate::entity::sea_orm_active_enums::OidcClientStatus::Active =>
        {
            Some((txn, client))
        }
        _ => None,
    })
}

/// 为页面生成新的 CSRF token（存摘要，返回明文）。
pub async fn issue_csrf(db: &DatabaseConnection, txn_id: Uuid) -> Result<String, AppError> {
    let token = secret::new_opaque_secret();
    oidc_auth_transactions::Entity::update_many()
        .col_expr(
            oidc_auth_transactions::Column::CsrfHash,
            Expr::value(secret::sha256_hex(&token)),
        )
        .filter(oidc_auth_transactions::Column::Id.eq(txn_id))
        .exec(db)
        .await?;
    Ok(token)
}

/// 常量时间校验 CSRF token。
pub fn csrf_matches(txn: &oidc_auth_transactions::Model, presented: &str) -> bool {
    use subtle::ConstantTimeEq;
    if !secret::is_plausible_token(presented) {
        return false;
    }
    secret::sha256_hex(presented)
        .as_bytes()
        .ct_eq(txn.csrf_hash.as_bytes())
        .into()
}

/// 记录本事务使用的会话/用户；`fresh_login` 表示本事务内刚输入过密码。
pub async fn bind_transaction_user(
    db: &DatabaseConnection,
    txn: oidc_auth_transactions::Model,
    user_id: Uuid,
    session_id: Uuid,
    fresh_login: bool,
) -> Result<oidc_auth_transactions::Model, AppError> {
    let mut active = txn.into_active_model();
    active.user_id = Set(Some(user_id));
    active.session_id = Set(Some(session_id));
    if fresh_login {
        active.authenticated_at = Set(Some(now()));
    }
    Ok(active.update(db).await?)
}

// ── 账号选择（prompt=select_account） ────────────────────────────────────────

/// 仍可推进的事务的公共条件：未完成、未过期。
fn live_txn_condition(id: Uuid) -> sea_orm::Condition {
    sea_orm::Condition::all()
        .add(oidc_auth_transactions::Column::Id.eq(id))
        .add(oidc_auth_transactions::Column::CompletedAt.is_null())
        .add(oidc_auth_transactions::Column::ExpiresAt.gt(now()))
}

/// 账号选择页渲染：生成新的 CSRF，并记下本次展示给用户的 SSO 会话。
///
/// 「继续使用此账号」只会确认**这个**会话；如果提交时浏览器 Cookie 已变成别的会话
/// （另一标签页切换了账号），提交会被拒绝并要求重新确认，而不是悄悄选中新账号。
pub async fn issue_account_choice_csrf(
    db: &DatabaseConnection,
    txn_id: Uuid,
    session_id: Uuid,
) -> Result<String, AppError> {
    let token = secret::new_opaque_secret();
    oidc_auth_transactions::Entity::update_many()
        .col_expr(
            oidc_auth_transactions::Column::CsrfHash,
            Expr::value(secret::sha256_hex(&token)),
        )
        .col_expr(
            oidc_auth_transactions::Column::AccountChoiceSessionId,
            Expr::value(Some(session_id)),
        )
        .filter(oidc_auth_transactions::Column::Id.eq(txn_id))
        .exec(db)
        .await?;
    Ok(token)
}

/// 「继续使用此账号」：原子确认账号选择并作废本页 CSRF。
///
/// 条件 UPDATE（未完成、未过期、未请求切换、尚未确认、展示的会话就是 `session_id`、
/// CSRF 摘要未被轮换）只有一个并发请求能命中；未命中返回 `Ok(None)`（双击 / 重放 / 页面已失效）。
pub async fn confirm_account_selection(
    db: &DatabaseConnection,
    txn_id: Uuid,
    session_id: Uuid,
    user_id: Uuid,
    presented_csrf: &str,
) -> Result<Option<oidc_auth_transactions::Model>, AppError> {
    let rows = oidc_auth_transactions::Entity::update_many()
        .col_expr(
            oidc_auth_transactions::Column::AccountSelectedAt,
            Expr::value(now()),
        )
        .col_expr(
            oidc_auth_transactions::Column::AccountSelectedSessionId,
            Expr::value(Some(session_id)),
        )
        .col_expr(
            oidc_auth_transactions::Column::UserId,
            Expr::value(Some(user_id)),
        )
        .col_expr(
            oidc_auth_transactions::Column::SessionId,
            Expr::value(Some(session_id)),
        )
        .col_expr(
            oidc_auth_transactions::Column::CsrfHash,
            Expr::value(secret::sha256_hex(&secret::new_opaque_secret())),
        )
        .filter(live_txn_condition(txn_id))
        .filter(oidc_auth_transactions::Column::AccountSwitchRequestedAt.is_null())
        .filter(oidc_auth_transactions::Column::AccountSelectedAt.is_null())
        .filter(oidc_auth_transactions::Column::AccountChoiceSessionId.eq(session_id))
        .filter(oidc_auth_transactions::Column::CsrfHash.eq(secret::sha256_hex(presented_csrf)))
        .exec_with_returning(db)
        .await?;
    Ok(rows.into_iter().next())
}

/// 「使用其他账号」：原子标记本事务要求切换账号，清空已有选择并作废本页 CSRF。
///
/// 之后旧 SSO 会话在本事务内不可用，直到用户在登录页重新输入密码。返回 false 表示事务已失效。
pub async fn request_account_switch(
    db: &DatabaseConnection,
    txn_id: Uuid,
    presented_csrf: &str,
) -> Result<bool, AppError> {
    let res = oidc_auth_transactions::Entity::update_many()
        .col_expr(
            oidc_auth_transactions::Column::AccountSwitchRequestedAt,
            Expr::value(now()),
        )
        .col_expr(
            oidc_auth_transactions::Column::AccountSelectedAt,
            Expr::value(Option::<DateTime<FixedOffset>>::None),
        )
        .col_expr(
            oidc_auth_transactions::Column::AccountSelectedSessionId,
            Expr::value(Option::<Uuid>::None),
        )
        .col_expr(
            oidc_auth_transactions::Column::CsrfHash,
            Expr::value(secret::sha256_hex(&secret::new_opaque_secret())),
        )
        .filter(live_txn_condition(txn_id))
        .filter(oidc_auth_transactions::Column::CsrfHash.eq(secret::sha256_hex(presented_csrf)))
        .exec(db)
        .await?;
    Ok(res.rows_affected == 1)
}

/// 本事务内输入密码登录成功：绑定新会话，并记为「已重新认证」+「已确认账号」
/// （输入密码本身就是一次明确的身份选择）。返回 `Ok(None)` 表示事务已被完成或过期。
pub async fn bind_password_login(
    db: &DatabaseConnection,
    txn_id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<Option<oidc_auth_transactions::Model>, AppError> {
    let now = now();
    let rows = oidc_auth_transactions::Entity::update_many()
        .col_expr(
            oidc_auth_transactions::Column::UserId,
            Expr::value(Some(user_id)),
        )
        .col_expr(
            oidc_auth_transactions::Column::SessionId,
            Expr::value(Some(session_id)),
        )
        .col_expr(
            oidc_auth_transactions::Column::AuthenticatedAt,
            Expr::value(Some(now)),
        )
        .col_expr(
            oidc_auth_transactions::Column::AccountSelectedAt,
            Expr::value(Some(now)),
        )
        .col_expr(
            oidc_auth_transactions::Column::AccountSelectedSessionId,
            Expr::value(Some(session_id)),
        )
        .filter(live_txn_condition(txn_id))
        .exec_with_returning(db)
        .await?;
    Ok(rows.into_iter().next())
}

/// 原子地把事务标记为完成；返回 false 表示已被其他请求完成（防重放/双击）。
pub async fn complete_transaction(db: &DatabaseConnection, id: Uuid) -> Result<bool, AppError> {
    let res = oidc_auth_transactions::Entity::update_many()
        .col_expr(
            oidc_auth_transactions::Column::CompletedAt,
            Expr::value(now()),
        )
        .filter(oidc_auth_transactions::Column::Id.eq(id))
        .filter(oidc_auth_transactions::Column::CompletedAt.is_null())
        .exec(db)
        .await?;
    Ok(res.rows_affected == 1)
}

// ── 授权码 ──────────────────────────────────────────────────────────────────

pub struct NewCode<'a> {
    pub client_pk: Uuid,
    pub user_id: Uuid,
    pub session_id: Option<Uuid>,
    pub redirect_uri: &'a str,
    pub scopes: &'a [String],
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub auth_time: DateTime<FixedOffset>,
    pub ttl_secs: i64,
}

/// 签发授权码，返回明文（只出现在本次重定向中）。
pub async fn insert_code(db: &DatabaseConnection, new: NewCode<'_>) -> Result<String, AppError> {
    let code = secret::new_authorization_code();
    let now = now();
    oidc_authorization_codes::ActiveModel {
        id: Set(Uuid::new_v4()),
        code_hash: Set(secret::sha256_hex(&code)),
        oidc_client_id: Set(new.client_pk),
        user_id: Set(new.user_id),
        session_id: Set(new.session_id),
        redirect_uri: Set(new.redirect_uri.to_string()),
        scopes: Set(scope::to_json(new.scopes)),
        nonce: Set(new.nonce),
        code_challenge_method: Set(new
            .code_challenge
            .as_ref()
            .map(|_| super::domain::pkce::METHOD_S256.to_string())),
        code_challenge: Set(new.code_challenge),
        auth_time: Set(new.auth_time),
        created_at: Set(now),
        expires_at: Set(now + Duration::seconds(new.ttl_secs)),
        consumed_at: Set(None),
    }
    .insert(db)
    .await?;
    Ok(code)
}

pub async fn find_code(
    db: &DatabaseConnection,
    code: &str,
) -> Result<Option<oidc_authorization_codes::Model>, AppError> {
    if !secret::is_plausible_token(code) {
        return Ok(None);
    }
    Ok(oidc_authorization_codes::Entity::find()
        .filter(oidc_authorization_codes::Column::CodeHash.eq(secret::sha256_hex(code)))
        .one(db)
        .await?)
}

/// 授权码重放：撤销由该授权码签发的全部 access token（RFC 6749 §4.1.2）。
pub async fn revoke_tokens_of_code<C: ConnectionTrait>(
    db: &C,
    code_id: Uuid,
) -> Result<u64, AppError> {
    let res = oidc_access_tokens::Entity::update_many()
        .col_expr(oidc_access_tokens::Column::RevokedAt, Expr::value(now()))
        .filter(oidc_access_tokens::Column::AuthorizationCodeId.eq(code_id))
        .filter(oidc_access_tokens::Column::RevokedAt.is_null())
        .exec(db)
        .await?;
    Ok(res.rows_affected)
}

/// 在同一个数据库事务中原子消费授权码并签发 access token。
///
/// 条件 UPDATE（未消费且未过期）只有一个并发请求能命中；未命中返回 `Ok(None)`。
pub async fn consume_code_and_issue_token(
    db: &DatabaseConnection,
    code: &oidc_authorization_codes::Model,
    access_token_ttl_secs: i64,
) -> Result<Option<(String, DateTime<FixedOffset>)>, AppError> {
    let txn = db.begin().await?;
    let now = now();
    let consumed = oidc_authorization_codes::Entity::update_many()
        .col_expr(
            oidc_authorization_codes::Column::ConsumedAt,
            Expr::value(now),
        )
        .filter(oidc_authorization_codes::Column::Id.eq(code.id))
        .filter(oidc_authorization_codes::Column::ConsumedAt.is_null())
        .filter(oidc_authorization_codes::Column::ExpiresAt.gt(now))
        .exec(&txn)
        .await?;
    if consumed.rows_affected != 1 {
        txn.rollback().await?;
        return Ok(None);
    }
    let token = secret::new_access_token();
    let expires_at = now + Duration::seconds(access_token_ttl_secs);
    oidc_access_tokens::ActiveModel {
        id: Set(Uuid::new_v4()),
        token_hash: Set(secret::sha256_hex(&token)),
        oidc_client_id: Set(code.oidc_client_id),
        user_id: Set(code.user_id),
        authorization_code_id: Set(Some(code.id)),
        scopes: Set(code.scopes.clone()),
        created_at: Set(now),
        expires_at: Set(expires_at),
        revoked_at: Set(None),
    }
    .insert(&txn)
    .await?;
    oidc_consents::Entity::update_many()
        .col_expr(oidc_consents::Column::LastUsedAt, Expr::value(now))
        .filter(oidc_consents::Column::UserId.eq(code.user_id))
        .filter(oidc_consents::Column::OidcClientId.eq(code.oidc_client_id))
        .exec(&txn)
        .await?;
    txn.commit().await?;
    Ok(Some((token, expires_at)))
}

// ── access token ───────────────────────────────────────────────────────────

/// UserInfo 用的令牌上下文：令牌、应用、用户都必须仍然有效。
pub struct TokenContext {
    pub token: oidc_access_tokens::Model,
    pub client: oidc_clients::Model,
    pub user: users::Model,
}

/// 查找可用于 UserInfo 的 access token：未过期、未撤销、应用 active、授权未撤销、用户存在。
pub async fn find_usable_token(
    db: &DatabaseConnection,
    token: &str,
) -> Result<Option<TokenContext>, AppError> {
    if !secret::is_plausible_token(token) {
        return Ok(None);
    }
    let Some((token_row, client)) = oidc_access_tokens::Entity::find()
        .filter(oidc_access_tokens::Column::TokenHash.eq(secret::sha256_hex(token)))
        .filter(oidc_access_tokens::Column::RevokedAt.is_null())
        .filter(oidc_access_tokens::Column::ExpiresAt.gt(now()))
        .find_also_related(oidc_clients::Entity)
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    let Some(client) = client else {
        return Ok(None);
    };
    if client.status != crate::entity::sea_orm_active_enums::OidcClientStatus::Active {
        return Ok(None);
    }
    let consent_ok = find_active_consent(db, token_row.user_id, client.id)
        .await?
        .is_some();
    if !consent_ok {
        return Ok(None);
    }
    let Some(user) = users::Entity::find_by_id(token_row.user_id).one(db).await? else {
        return Ok(None);
    };
    Ok(Some(TokenContext {
        token: token_row,
        client,
        user,
    }))
}

/// 撤销某用户对某应用的全部 access token 与未使用的授权码。
pub async fn revoke_user_client_grants<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    client_pk: Uuid,
) -> Result<(), AppError> {
    let now = now();
    oidc_access_tokens::Entity::update_many()
        .col_expr(oidc_access_tokens::Column::RevokedAt, Expr::value(now))
        .filter(oidc_access_tokens::Column::UserId.eq(user_id))
        .filter(oidc_access_tokens::Column::OidcClientId.eq(client_pk))
        .filter(oidc_access_tokens::Column::RevokedAt.is_null())
        .exec(db)
        .await?;
    // 未兑换的授权码一并作废（标记为已消费，兑换时按重放处理）。
    oidc_authorization_codes::Entity::update_many()
        .col_expr(
            oidc_authorization_codes::Column::ConsumedAt,
            Expr::value(now),
        )
        .filter(oidc_authorization_codes::Column::UserId.eq(user_id))
        .filter(oidc_authorization_codes::Column::OidcClientId.eq(client_pk))
        .filter(oidc_authorization_codes::Column::ConsumedAt.is_null())
        .exec(db)
        .await?;
    Ok(())
}

// ── 用户授权 ────────────────────────────────────────────────────────────────

pub async fn find_active_consent(
    db: &DatabaseConnection,
    user_id: Uuid,
    client_pk: Uuid,
) -> Result<Option<oidc_consents::Model>, AppError> {
    Ok(oidc_consents::Entity::find()
        .filter(oidc_consents::Column::UserId.eq(user_id))
        .filter(oidc_consents::Column::OidcClientId.eq(client_pk))
        .filter(oidc_consents::Column::RevokedAt.is_null())
        .one(db)
        .await?)
}

/// 记录授权：已有有效授权取并集，已撤销的授权重新生效（只含本次 scope）。
pub async fn grant_consent(
    db: &DatabaseConnection,
    user_id: Uuid,
    client_pk: Uuid,
    scopes: &[String],
) -> Result<Vec<String>, AppError> {
    let existing = oidc_consents::Entity::find()
        .filter(oidc_consents::Column::UserId.eq(user_id))
        .filter(oidc_consents::Column::OidcClientId.eq(client_pk))
        .one(db)
        .await?;
    let now = now();
    match existing {
        Some(row) => {
            let merged = if row.revoked_at.is_none() {
                scope::union(&scope::from_json(&row.scopes), scopes)
            } else {
                scope::union(scopes, &[])
            };
            let was_revoked = row.revoked_at.is_some();
            let mut active = row.into_active_model();
            active.scopes = Set(scope::to_json(&merged));
            active.updated_at = Set(now);
            if was_revoked {
                active.revoked_at = Set(None);
                active.granted_at = Set(now);
            }
            active.update(db).await?;
            Ok(merged)
        }
        None => {
            let merged = scope::union(scopes, &[]);
            let insert = oidc_consents::ActiveModel {
                id: Set(Uuid::new_v4()),
                user_id: Set(user_id),
                oidc_client_id: Set(client_pk),
                scopes: Set(scope::to_json(&merged)),
                granted_at: Set(now),
                updated_at: Set(now),
                last_used_at: Set(None),
                revoked_at: Set(None),
            };
            // 并发首授（双击）时以唯一约束兜底，冲突即更新 scope。
            oidc_consents::Entity::insert(insert)
                .on_conflict(
                    OnConflict::columns([
                        oidc_consents::Column::UserId,
                        oidc_consents::Column::OidcClientId,
                    ])
                    .update_columns([
                        oidc_consents::Column::Scopes,
                        oidc_consents::Column::UpdatedAt,
                    ])
                    .to_owned(),
                )
                .exec(db)
                .await?;
            Ok(merged)
        }
    }
}

/// 用户撤销授权：标记授权撤销 + 撤销令牌 + 作废未用授权码（同一事务）。
pub async fn revoke_consent(
    db: &DatabaseConnection,
    user_id: Uuid,
    client_pk: Uuid,
) -> Result<bool, AppError> {
    let txn = db.begin().await?;
    let res = oidc_consents::Entity::update_many()
        .col_expr(oidc_consents::Column::RevokedAt, Expr::value(now()))
        .filter(oidc_consents::Column::UserId.eq(user_id))
        .filter(oidc_consents::Column::OidcClientId.eq(client_pk))
        .filter(oidc_consents::Column::RevokedAt.is_null())
        .exec(&txn)
        .await?;
    revoke_user_client_grants(&txn, user_id, client_pk).await?;
    txn.commit().await?;
    Ok(res.rows_affected > 0)
}

/// 用户的有效授权列表（含应用）。
pub async fn list_user_consents(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Vec<(oidc_consents::Model, oidc_clients::Model)>, AppError> {
    let rows = oidc_consents::Entity::find()
        .filter(oidc_consents::Column::UserId.eq(user_id))
        .filter(oidc_consents::Column::RevokedAt.is_null())
        .find_also_related(oidc_clients::Entity)
        .order_by_desc(oidc_consents::Column::UpdatedAt)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(consent, client)| client.map(|c| (consent, c)))
        .collect())
}

// ── 清理 ────────────────────────────────────────────────────────────────────

/// 清理统计。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupStats {
    pub transactions: u64,
    pub codes: u64,
    pub access_tokens: u64,
    pub sessions: u64,
}

/// 删除已过期的短期数据（保留 1 天以便排障；撤销/过期会话保留 7 天）。
pub async fn cleanup_expired(db: &DatabaseConnection) -> Result<CleanupStats, AppError> {
    let day_ago = now() - Duration::days(1);
    let week_ago = now() - Duration::days(7);
    let transactions = oidc_auth_transactions::Entity::delete_many()
        .filter(oidc_auth_transactions::Column::ExpiresAt.lt(day_ago))
        .exec(db)
        .await?
        .rows_affected;
    let access_tokens = oidc_access_tokens::Entity::delete_many()
        .filter(oidc_access_tokens::Column::ExpiresAt.lt(day_ago))
        .exec(db)
        .await?
        .rows_affected;
    let codes = oidc_authorization_codes::Entity::delete_many()
        .filter(oidc_authorization_codes::Column::ExpiresAt.lt(day_ago))
        .exec(db)
        .await?
        .rows_affected;
    let sessions = oidc_browser_sessions::Entity::delete_many()
        .filter(
            sea_orm::Condition::any()
                .add(oidc_browser_sessions::Column::ExpiresAt.lt(week_ago))
                .add(oidc_browser_sessions::Column::RevokedAt.lt(week_ago)),
        )
        .exec(db)
        .await?
        .rows_affected;
    Ok(CleanupStats {
        transactions,
        codes,
        access_tokens,
        sessions,
    })
}
