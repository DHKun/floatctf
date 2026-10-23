//! 平台登录 ↔ OIDC SSO 会话的衔接（`/api/users/sso`）。
//!
//! - 平台登录 `POST /api/users/session` 成功后调用 [`establish_after_password_login`] 下发 SSO Cookie；
//! - `POST /api/users/sso`：本功能上线前已持有平台 JWT 的 SPA 会话，用 Bearer JWT 换取 SSO Cookie（幂等）；
//! - `DELETE /api/users/sso`：SPA 登出时撤销服务端 SSO 会话（不依赖 localStorage 清理）。

use actix_web::{HttpRequest, HttpResponse, cookie::Cookie, delete, http::header, post};
use chrono::{TimeZone, Utc};
use uuid::Uuid;

use super::protocol::{removal_cookie, same_origin, sso_cookie, sso_cookie_name, sso_cookie_value};
use crate::api::{AppError, UniResponse, extractor::auth::UserJwtGuard};
use crate::core::security::jwt::validate_jwt;
use crate::infrastructure::WebDb;
use crate::modules::identity::oidc::{OidcProvider, WebOidc, store};

/// 平台 JWT 默认有效期（`gen_jwt_token` 缺省 8h），用于推算旧 JWT（无 `iat`）的签发时间。
const PLATFORM_JWT_DEFAULT_TTL_SECS: i64 = 8 * 3600;

/// 平台口令登录成功后建立 SSO 会话，返回要下发的 Cookie。
pub async fn establish_after_password_login(
    db: &sea_orm::DatabaseConnection,
    oidc: &OidcProvider,
    req: &HttpRequest,
    user_id: Uuid,
) -> Result<Cookie<'static>, AppError> {
    // 同一浏览器的旧会话（可能是另一个账号）先撤销，避免会话串号。
    if let Some(old) = sso_cookie_value(req, oidc) {
        store::revoke_session(db, &old).await?;
    }
    let (value, _) = store::create_session(
        db,
        user_id,
        Utc::now().fixed_offset(),
        oidc.config.session_ttl_secs,
        store::SessionOrigin::PasswordLogin,
    )
    .await?;
    Ok(sso_cookie(oidc, value))
}

#[derive(serde::Serialize)]
pub struct SsoBridgeResult {
    /// 本次是否新建了会话（false = 已有同用户的有效会话，幂等返回）。
    pub established: bool,
}

/// POST /api/users/sso —— 用平台 JWT 建立 SSO 会话（幂等）。
#[post("/sso")]
pub async fn bridge(
    req: HttpRequest,
    user: UserJwtGuard,
    oidc: Option<WebOidc>,
    db: WebDb,
) -> Result<HttpResponse, AppError> {
    let Some(oidc) = oidc else {
        return Err(AppError::NotFound("OIDC 未启用".into()));
    };
    let user = user.into_inner();
    if let Some(current) = sso_cookie_value(&req, &oidc)
        && let Some((_, session_user)) = store::find_valid_session(&db, &current).await?
        && session_user.id == user.id
    {
        return Ok(
            HttpResponse::Ok().json(UniResponse::ok(Some(SsoBridgeResult {
                established: false,
            }))),
        );
    }

    // UserJwtGuard 已验证过签名；这里只为读取 iat/exp。
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .ok_or(AppError::Unauthorized)?;
    let claims = validate_jwt(token.to_string()).map_err(|_| AppError::Unauthorized)?;
    let now = Utc::now().timestamp();
    let exp = claims.exp as i64;
    // auth_time 取 JWT 签发时间，而不是"现在"——桥接不是一次新的认证。
    let issued_at = claims
        .iat
        .map(|iat| iat as i64)
        .unwrap_or(exp - PLATFORM_JWT_DEFAULT_TTL_SECS)
        .min(now);
    let auth_time = Utc
        .timestamp_opt(issued_at, 0)
        .single()
        .ok_or(AppError::Unauthorized)?
        .fixed_offset();
    // 会话不比平台 JWT 活得更久。
    let ttl = oidc.config.session_ttl_secs.min(exp - now);
    if ttl <= 0 {
        return Err(AppError::Unauthorized);
    }
    if let Some(old) = sso_cookie_value(&req, &oidc) {
        store::revoke_session(&db, &old).await?;
    }
    let (value, _) = store::create_session(
        &db,
        user.id,
        auth_time,
        ttl,
        store::SessionOrigin::JwtBridge,
    )
    .await?;
    let mut cookie = sso_cookie(&oidc, value);
    cookie.set_max_age(actix_web::cookie::time::Duration::seconds(ttl));
    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(UniResponse::ok(Some(SsoBridgeResult { established: true }))))
}

/// DELETE /api/users/sso —— 撤销当前浏览器的 SSO 会话并清除 Cookie。
#[delete("/sso")]
pub async fn sign_out(
    req: HttpRequest,
    oidc: Option<WebOidc>,
    db: WebDb,
) -> Result<HttpResponse, AppError> {
    let Some(oidc) = oidc else {
        // 未启用 OIDC 时没有 SSO 会话可清理；保持幂等成功，前端无需区分。
        return Ok(HttpResponse::Ok().json(UniResponse::<()>::ok_none()));
    };
    if !same_origin(&req, &oidc) {
        return Err(AppError::Forbidden("跨站请求被拒绝".into()));
    }
    if let Some(value) = sso_cookie_value(&req, &oidc) {
        store::revoke_session(&db, &value).await?;
    }
    Ok(HttpResponse::Ok()
        .cookie(removal_cookie(
            sso_cookie_name(oidc.secure_cookies()),
            oidc.secure_cookies(),
        ))
        .json(UniResponse::<()>::ok_none()))
}
