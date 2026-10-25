//! 协议端点：authorize / login / select-account / consent / token / userinfo / logout。

use actix_web::{
    HttpRequest, HttpResponse,
    cookie::{Cookie, SameSite, time::Duration as CookieDuration},
    get,
    http::{StatusCode, header},
    post, route, web,
};
use serde_json::json;
use uuid::Uuid;

use super::{not_enabled, pages};
use crate::infrastructure::{LogService, WebDb, WebLog};
use crate::modules::identity::oidc::{
    OidcProvider, WebOidc,
    domain::{
        authorize::{Prompt, RawParams},
        client_auth,
        error::OAuthError,
        metadata::{PATH_CONSENT, PATH_LOGIN, PATH_SELECT_ACCOUNT},
        scope, secret,
    },
    flow::{self, Next},
    store,
};

// ── Cookie ──────────────────────────────────────────────────────────────────

/// SSO 会话 Cookie 名。https issuer 使用 `__Host-` 前缀（强制 Secure、Path=/、无 Domain）。
pub fn sso_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-fctf_sso"
    } else {
        "fctf_sso"
    }
}

/// 浏览器绑定 Cookie 名（授权事务只能在发起它的浏览器内推进）。
pub fn binding_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-fctf_bid"
    } else {
        "fctf_bid"
    }
}

const BINDING_COOKIE_MAX_AGE_SECS: i64 = 30 * 24 * 3600;

pub fn build_cookie(
    name: &'static str,
    value: String,
    max_age_secs: i64,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build(name, value)
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(max_age_secs))
        .finish()
}

pub fn removal_cookie(name: &'static str, secure: bool) -> Cookie<'static> {
    let mut cookie = build_cookie(name, String::new(), 0, secure);
    cookie.make_removal();
    cookie
}

/// 设置 SSO Cookie（登录成功后调用）。
pub fn sso_cookie(oidc: &OidcProvider, value: String) -> Cookie<'static> {
    build_cookie(
        sso_cookie_name(oidc.secure_cookies()),
        value,
        oidc.config.session_ttl_secs,
        oidc.secure_cookies(),
    )
}

fn cookie_value(req: &HttpRequest, name: &str) -> Option<String> {
    req.cookie(name).map(|c| c.value().to_string())
}

pub fn sso_cookie_value(req: &HttpRequest, oidc: &OidcProvider) -> Option<String> {
    cookie_value(req, sso_cookie_name(oidc.secure_cookies()))
}

// ── 请求解析与通用响应 ───────────────────────────────────────────────────────

fn parse_pairs(raw: &[u8]) -> RawParams {
    RawParams::from_pairs(
        url::form_urlencoded::parse(raw).map(|(k, v)| (k.into_owned(), v.into_owned())),
    )
}

fn is_form(req: &HttpRequest) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// 状态变更表单的同源校验：有 `Origin` 时必须等于 issuer；否则看 `Sec-Fetch-Site`。
pub fn same_origin(req: &HttpRequest, oidc: &OidcProvider) -> bool {
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        return origin.to_str().is_ok_and(|o| o == oidc.issuer());
    }
    match req
        .headers()
        .get("Sec-Fetch-Site")
        .and_then(|v| v.to_str().ok())
    {
        Some(site) => matches!(site, "same-origin" | "none"),
        None => true,
    }
}

fn no_store(mut builder: actix_web::HttpResponseBuilder) -> actix_web::HttpResponseBuilder {
    builder
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"));
    builder
}

fn redirect(location: &str) -> actix_web::HttpResponseBuilder {
    let mut builder = no_store(HttpResponse::Found());
    builder.insert_header((header::LOCATION, location.to_string()));
    builder
}

fn respond(next: Next, cookies: Vec<Cookie<'static>>) -> HttpResponse {
    let mut resp = match next {
        Next::RedirectToClient(url) | Next::RedirectLocal(url) => redirect(&url).finish(),
        Next::ErrorPage { status, message } => pages::error_page(status, &message),
    };
    for cookie in cookies {
        let _ = resp.add_cookie(&cookie);
    }
    resp
}

fn server_error_page() -> HttpResponse {
    pages::error_page(500, "服务暂时不可用，请稍后重试。")
}

fn audit(
    log: &WebLog,
    level: &str,
    action: &str,
    message: String,
    details: serde_json::Value,
    user_id: Option<Uuid>,
    req: &HttpRequest,
) {
    let log = log.clone();
    let level = level.to_string();
    let action = action.to_string();
    let req = req.clone();
    actix_web::rt::spawn(async move {
        log.add_log(
            &level,
            "OIDC",
            &action,
            &message,
            details,
            user_id,
            None,
            Some(&req),
        )
        .await;
    });
}

// ── 授权端点 ────────────────────────────────────────────────────────────────

/// GET|POST /oauth/authorize（OIDC Core §3.1.2.1：两种方法都必须支持）
#[route("/oauth/authorize", method = "GET", method = "POST")]
pub async fn authorize(
    req: HttpRequest,
    body: web::Bytes,
    oidc: Option<WebOidc>,
    db: WebDb,
) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    let params = if req.method() == actix_web::http::Method::POST {
        if !is_form(&req) {
            return pages::error_page(400, "授权请求必须使用 application/x-www-form-urlencoded。");
        }
        parse_pairs(&body)
    } else {
        parse_pairs(req.query_string().as_bytes())
    };

    let secure = oidc.secure_cookies();
    let binding_name = binding_cookie_name(secure);
    let (binding, new_binding) =
        match cookie_value(&req, binding_name).filter(|v| secret::is_plausible_token(v)) {
            Some(v) => (v, None),
            None => {
                let v = flow::new_browser_binding();
                (
                    v.clone(),
                    Some(build_cookie(
                        binding_name,
                        v,
                        BINDING_COOKIE_MAX_AGE_SECS,
                        secure,
                    )),
                )
            }
        };

    let result = async {
        let session = flow::current_session(&db, sso_cookie_value(&req, &oidc).as_deref()).await?;
        flow::start(&db, &oidc, &params, &binding, session).await
    }
    .await;
    match result {
        Ok(next) => respond(next, new_binding.into_iter().collect()),
        Err(e) => {
            tracing::error!(error = %e, "OIDC authorize failed");
            server_error_page()
        }
    }
}

// ── 登录页 ──────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct TxnQuery {
    txn: Option<String>,
}

async fn render_login(
    db: &WebDb,
    txn: &crate::entity::oidc_auth_transactions::Model,
    client: &crate::entity::oidc_clients::Model,
    username: &str,
    error: Option<&str>,
    status: StatusCode,
) -> HttpResponse {
    let csrf = match store::issue_csrf(db, txn.id).await {
        Ok(c) => c,
        Err(_) => return server_error_page(),
    };
    let prompt = Prompt::from_values(&scope::from_json(&txn.prompt));
    let switching = txn.account_switch_requested_at.is_some();
    pages::html(
        status,
        "login.html",
        minijinja::context! {
            action => PATH_LOGIN,
            txn => txn.id.to_string(),
            csrf => csrf,
            client_name => client.name.clone(),
            client_host => pages::host_of(client.homepage_url.as_deref()),
            username => username,
            error => error,
            reauth => !switching && (prompt.login || txn.max_age.is_some()),
            switching => switching,
        },
        &rp_form_action_origins(txn, client),
    )
}

/// 表单提交后可能 302 去往的 RP origin（CSP form-action）。
fn rp_form_action_origins(
    txn: &crate::entity::oidc_auth_transactions::Model,
    client: &crate::entity::oidc_clients::Model,
) -> Vec<String> {
    let redirect_origin = pages::origin_of(&txn.redirect_uri);
    let homepage_origin = client.homepage_url.as_deref().and_then(pages::origin_of);
    pages::form_action_origins(redirect_origin.as_deref(), homepage_origin.as_deref())
}

/// 登录页预填的用户名（只是便利，从不作为身份依据）：
/// 用户在选择页确认了账号、随后被要求重新认证（`select_account login` / `max_age`）时预填该账号；
/// 选择「使用其他账号」时不预填当前账号；否则用 RP 的 `login_hint`。
async fn login_prefill(
    db: &WebDb,
    txn: &crate::entity::oidc_auth_transactions::Model,
) -> Result<String, crate::api::AppError> {
    use sea_orm::EntityTrait;
    if txn.account_switch_requested_at.is_none()
        && txn.account_selected_at.is_some()
        && let Some(user_id) = txn.user_id
        && let Some(user) = crate::entity::users::Entity::find_by_id(user_id)
            .one(db.get_ref())
            .await?
    {
        return Ok(user.username);
    }
    Ok(txn.login_hint.clone().unwrap_or_default())
}

/// GET /oauth/login?txn=…
#[get("/oauth/login")]
pub async fn login_page(
    req: HttpRequest,
    query: web::Query<TxnQuery>,
    oidc: Option<WebOidc>,
    db: WebDb,
) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    let Some(txn_id) = flow::parse_txn_id(query.txn.as_deref()) else {
        return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE);
    };
    let binding = cookie_value(&req, binding_cookie_name(oidc.secure_cookies()));
    match store::find_live_transaction(&db, txn_id, binding.as_deref()).await {
        Ok(Some((txn, client))) => match login_prefill(&db, &txn).await {
            Ok(hint) => render_login(&db, &txn, &client, &hint, None, StatusCode::OK).await,
            Err(_) => server_error_page(),
        },
        Ok(None) => pages::error_page(400, flow::TXN_EXPIRED_MESSAGE),
        Err(_) => server_error_page(),
    }
}

/// 登录尝试限流（Redis 共享窗口，故障 fail-closed），5 分钟窗口：
/// 同一用户名默认 10 次、同一来源 IP 默认 50 次；运维可在设置表调整
/// `OIDC_LOGIN_RATE_PER_USER` / `OIDC_LOGIN_RATE_PER_IP`（缺省或非法时用默认值）。
async fn login_rate_ok(
    db: &sea_orm::DatabaseConnection,
    oidc: &OidcProvider,
    username: &str,
    ip: &str,
) -> Result<bool, String> {
    let limit = |key: &'static str, default: u32| async move {
        crate::infrastructure::get_setting(db, key)
            .await
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default)
    };
    let per_user = limit("OIDC_LOGIN_RATE_PER_USER", 10).await;
    let per_ip = limit("OIDC_LOGIN_RATE_PER_IP", 50).await;
    let user_key = secret::sha256_hex(&username.to_lowercase());
    Ok(oidc
        .rate
        .hit("oidc_login_user", &user_key, per_user, 300)
        .await?
        && oidc.rate.hit("oidc_login_ip", ip, per_ip, 300).await?)
}

/// POST /oauth/login
#[post("/oauth/login")]
pub async fn login_submit(
    req: HttpRequest,
    body: web::Bytes,
    oidc: Option<WebOidc>,
    db: WebDb,
    log: WebLog,
) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    if !is_form(&req) || !same_origin(&req, &oidc) {
        return pages::error_page(400, "请求来源无效。");
    }
    let form = parse_pairs(&body);
    let field = |name: &str| {
        form.single(name)
            .ok()
            .flatten()
            .unwrap_or_default()
            .to_string()
    };
    let Some(txn_id) = flow::parse_txn_id(Some(&field("txn"))) else {
        return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE);
    };
    let binding = cookie_value(&req, binding_cookie_name(oidc.secure_cookies()));
    let (txn, client) = match store::find_live_transaction(&db, txn_id, binding.as_deref()).await {
        Ok(Some(found)) => found,
        Ok(None) => return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE),
        Err(_) => return server_error_page(),
    };
    if !store::csrf_matches(&txn, &field("csrf")) {
        return pages::error_page(400, "页面已失效（CSRF 校验失败），请返回应用重新登录。");
    }

    if field("action") == "cancel" {
        audit(
            &log,
            "INFO",
            "OIDC_LOGIN_CANCEL",
            format!("取消登录授权 {}", client.client_id),
            json!({"client_id": client.client_id}),
            None,
            &req,
        );
        return match flow::finish_with_error(
            &db,
            &oidc,
            &txn,
            OAuthError::access_denied("user cancelled login"),
        )
        .await
        {
            Ok(next) => respond(next, vec![]),
            Err(_) => server_error_page(),
        };
    }

    let username = field("username").trim().to_string();
    let password = field("password");
    if username.is_empty()
        || password.is_empty()
        || username.chars().count() > 64
        || password.len() > 256
    {
        return render_login(
            &db,
            &txn,
            &client,
            &username,
            Some("请输入用户名和密码。"),
            StatusCode::OK,
        )
        .await;
    }
    let ip = LogService::get_client_ip(&req).unwrap_or_else(|| "unknown".into());
    match login_rate_ok(&db, &oidc, &username, &ip).await {
        Ok(true) => {}
        Ok(false) => {
            return render_login(
                &db,
                &txn,
                &client,
                &username,
                Some("尝试次数过多，请稍后再试。"),
                StatusCode::TOO_MANY_REQUESTS,
            )
            .await;
        }
        Err(e) => {
            tracing::error!(error = %e, "OIDC login rate limiter unavailable (fail-closed)");
            return pages::error_page(503, "服务暂时不可用，请稍后重试。");
        }
    }

    let verified = crate::modules::identity::authentication::verify_user_credentials(
        &db, &username, &password,
    )
    .await;
    let user = match verified {
        Ok((Some(user), true)) => user,
        Ok((maybe_user, _)) => {
            audit(
                &log,
                "ERROR",
                "OIDC_LOGIN_FAILED",
                "OIDC 登录失败".to_string(),
                json!({"client_id": client.client_id}),
                maybe_user.map(|u| u.id),
                &req,
            );
            return render_login(
                &db,
                &txn,
                &client,
                &username,
                Some("用户名或密码错误。"),
                StatusCode::OK,
            )
            .await;
        }
        Err(_) => return server_error_page(),
    };

    // RP 用 id_token_hint 指定了账号：其他账号的正确密码也不能建立会话或发码，
    // 且不撤销浏览器当前的 SSO。
    if txn
        .id_token_hint_sub
        .as_deref()
        .is_some_and(|sub| sub != user.id.to_string())
    {
        audit(
            &log,
            "WARN",
            "OIDC_LOGIN_HINT_MISMATCH",
            format!("{} 登录的账号与应用指定的账号不一致", user.username),
            json!({"client_id": client.client_id}),
            Some(user.id),
            &req,
        );
        return render_login(
            &db,
            &txn,
            &client,
            "",
            Some("该应用要求使用指定的 FloatCTF 账号登录，请改用该账号。"),
            StatusCode::OK,
        )
        .await;
    }

    // 新会话（auth_time=now）；同一浏览器旧会话（可能是另一个账号）一并撤销。
    if let Some(old) = sso_cookie_value(&req, &oidc) {
        let _ = store::revoke_session(&db, &old).await;
    }
    let (cookie, session) = match store::create_session(
        &db,
        user.id,
        chrono::Utc::now().fixed_offset(),
        oidc.config.session_ttl_secs,
        store::SessionOrigin::OidcLogin,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return server_error_page(),
    };
    audit(
        &log,
        "INFO",
        "OIDC_LOGIN",
        format!("{} 通过 OIDC 登录页登录", user.username),
        json!({
            "client_id": client.client_id,
            "account_switch": txn.account_switch_requested_at.is_some(),
        }),
        Some(user.id),
        &req,
    );

    // 本事务内输入密码 = 已重新认证 + 已明确选择该账号。
    let next = async {
        match store::bind_password_login(&db, txn.id, user.id, session.id).await? {
            Some(txn) => flow::advance(&db, &oidc, txn, &client, Some((session, user))).await,
            None => Ok(Next::ErrorPage {
                status: 400,
                message: flow::TXN_EXPIRED_MESSAGE.into(),
            }),
        }
    }
    .await;
    // 旧会话已撤销：无论事务能否继续，都要把新会话 Cookie 交给浏览器。
    match next {
        Ok(next) => respond(next, vec![sso_cookie(&oidc, cookie)]),
        Err(_) => {
            let mut resp = server_error_page();
            let _ = resp.add_cookie(&sso_cookie(&oidc, cookie));
            resp
        }
    }
}

// ── 同意页 ──────────────────────────────────────────────────────────────────

/// GET /oauth/consent?txn=…
#[get("/oauth/consent")]
pub async fn consent_page(
    req: HttpRequest,
    query: web::Query<TxnQuery>,
    oidc: Option<WebOidc>,
    db: WebDb,
) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    let Some(txn_id) = flow::parse_txn_id(query.txn.as_deref()) else {
        return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE);
    };
    let binding = cookie_value(&req, binding_cookie_name(oidc.secure_cookies()));
    let result = async {
        let Some((txn, client)) =
            store::find_live_transaction(&db, txn_id, binding.as_deref()).await?
        else {
            return Ok(Err(Next::ErrorPage {
                status: 400,
                message: flow::TXN_EXPIRED_MESSAGE.into(),
            }));
        };
        let session = flow::current_session(&db, sso_cookie_value(&req, &oidc).as_deref()).await?;
        match flow::consent_ready(&db, &oidc, &txn, &client, session.clone()).await? {
            Some((_, user)) => {
                let previous = store::find_active_consent(&db, user.id, client.id).await?;
                Ok(Ok((txn, client, user, previous)))
            }
            // 会话变化（过期/另一个标签页切换了账号）、尚未选择账号、已要求切换账号 → 重新走决策。
            None => Ok(Err(flow::advance(&db, &oidc, txn, &client, session).await?)),
        }
    }
    .await;
    let (txn, client, user, previous) = match result {
        Ok(Ok(v)) => v,
        Ok(Err(next)) => return respond(next, vec![]),
        Err::<_, crate::api::AppError>(_) => return server_error_page(),
    };
    let csrf = match store::issue_csrf(&db, txn.id).await {
        Ok(c) => c,
        Err(_) => return server_error_page(),
    };
    let previously = previous
        .map(|c| scope::from_json(&c.scopes))
        .unwrap_or_default();
    let items: Vec<_> = scope::from_json(&txn.scopes)
        .iter()
        .filter_map(|s| pages::scope_item(s, previously.contains(s)))
        .collect();
    let form_action_origins = rp_form_action_origins(&txn, &client);
    pages::html(
        StatusCode::OK,
        "consent.html",
        minijinja::context! {
            action => PATH_CONSENT,
            txn => txn.id.to_string(),
            csrf => csrf,
            client_name => client.name.clone(),
            client_host => pages::host_of(client.homepage_url.as_deref()),
            user_display => format!("{}（@{}）", user.nickname, user.username),
            scopes => items,
        },
        &form_action_origins,
    )
}

/// POST /oauth/consent
#[post("/oauth/consent")]
pub async fn consent_submit(
    req: HttpRequest,
    body: web::Bytes,
    oidc: Option<WebOidc>,
    db: WebDb,
    log: WebLog,
) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    if !is_form(&req) || !same_origin(&req, &oidc) {
        return pages::error_page(400, "请求来源无效。");
    }
    let form = parse_pairs(&body);
    let field = |name: &str| {
        form.single(name)
            .ok()
            .flatten()
            .unwrap_or_default()
            .to_string()
    };
    let Some(txn_id) = flow::parse_txn_id(Some(&field("txn"))) else {
        return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE);
    };
    let binding = cookie_value(&req, binding_cookie_name(oidc.secure_cookies()));
    let (txn, client) = match store::find_live_transaction(&db, txn_id, binding.as_deref()).await {
        Ok(Some(found)) => found,
        Ok(None) => return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE),
        Err(_) => return server_error_page(),
    };
    if !store::csrf_matches(&txn, &field("csrf")) {
        return pages::error_page(400, "页面已失效（CSRF 校验失败），请返回应用重新登录。");
    }
    let action = field("action");
    if action == "switch" {
        // 同意页上的「使用其他账号」（含旧版页面的「切换账号」）与选择页走同一个状态转移：
        // 记录切换意图后强制输入密码，旧 SSO 不能再短路本事务。
        return account_switch(&db, &log, &req, &txn, &client, &field("csrf")).await;
    }

    let session = match flow::current_session(&db, sso_cookie_value(&req, &oidc).as_deref()).await {
        Ok(s) => s,
        Err(_) => return server_error_page(),
    };
    let (session, user) =
        match flow::consent_ready(&db, &oidc, &txn, &client, session.clone()).await {
            Ok(Some(ready)) => ready,
            Ok(None) => {
                return match flow::advance(&db, &oidc, txn, &client, session).await {
                    Ok(next) => respond(next, vec![]),
                    Err(_) => server_error_page(),
                };
            }
            Err(_) => return server_error_page(),
        };

    let result = if action == "allow" {
        let selected: Vec<String> = form
            .0
            .iter()
            .filter(|(k, _)| k == "scope")
            .map(|(_, v)| v.clone())
            .collect();
        let granted = flow::granted_from_selection(&scope::from_json(&txn.scopes), &selected);
        audit(
            &log,
            "INFO",
            "OIDC_CONSENT_GRANT",
            format!("{} 授权应用 {}", user.username, client.name),
            json!({"client_id": client.client_id, "scopes": granted}),
            Some(user.id),
            &req,
        );
        async {
            store::grant_consent(&db, user.id, client.id, &granted).await?;
            flow::issue_code(&db, &oidc, &txn, &client, &session, &user, &granted).await
        }
        .await
    } else {
        audit(
            &log,
            "INFO",
            "OIDC_CONSENT_DENY",
            format!("{} 拒绝授权应用 {}", user.username, client.name),
            json!({"client_id": client.client_id}),
            Some(user.id),
            &req,
        );
        flow::finish_with_error(
            &db,
            &oidc,
            &txn,
            OAuthError::access_denied("user denied the request"),
        )
        .await
    };
    match result {
        Ok(next) => respond(next, vec![]),
        Err(_) => server_error_page(),
    }
}

// ── 账号选择页（prompt=select_account） ─────────────────────────────────────

/// 「使用其他账号」：记录切换意图（并作废当前页 CSRF），然后去登录页强制输入密码。
async fn account_switch(
    db: &WebDb,
    log: &WebLog,
    req: &HttpRequest,
    txn: &crate::entity::oidc_auth_transactions::Model,
    client: &crate::entity::oidc_clients::Model,
    presented_csrf: &str,
) -> HttpResponse {
    match store::request_account_switch(db, txn.id, presented_csrf).await {
        Ok(true) => {
            audit(
                log,
                "INFO",
                "OIDC_ACCOUNT_SWITCH",
                format!("应用 {} 的授权中选择使用其他账号", client.client_id),
                json!({"client_id": client.client_id}),
                None,
                req,
            );
            redirect(&format!("{PATH_LOGIN}?txn={}", txn.id)).finish()
        }
        Ok(false) => pages::error_page(400, flow::TXN_EXPIRED_MESSAGE),
        Err(_) => server_error_page(),
    }
}

/// 账号选择页只展示同源相对路径头像（CSP `img-src 'self'`）；其余情况显示首字母。
fn same_origin_avatar(avatar: Option<&str>) -> Option<String> {
    avatar
        .filter(|a| a.starts_with('/') && !a.starts_with("//") && !a.contains('\\'))
        .map(str::to_string)
}

async fn render_select_account(
    db: &WebDb,
    txn: &crate::entity::oidc_auth_transactions::Model,
    client: &crate::entity::oidc_clients::Model,
    current: &flow::SessionUser,
    account_changed: bool,
) -> HttpResponse {
    let (session, user) = current;
    let csrf = match store::issue_account_choice_csrf(db, txn.id, session.id).await {
        Ok(c) => c,
        Err(_) => return server_error_page(),
    };
    let initial = user
        .nickname
        .chars()
        .next()
        .or_else(|| user.username.chars().next())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    pages::html(
        StatusCode::OK,
        "select_account.html",
        minijinja::context! {
            action => PATH_SELECT_ACCOUNT,
            txn => txn.id.to_string(),
            csrf => csrf,
            client_name => client.name.clone(),
            client_host => pages::host_of(client.homepage_url.as_deref()),
            nickname => user.nickname.clone(),
            username => user.username.clone(),
            avatar => same_origin_avatar(user.avatar.as_deref()),
            initial => initial,
            account_changed => account_changed,
        },
        &rp_form_action_origins(txn, client),
    )
}

/// GET /oauth/select-account?txn=…
///
/// 纯渲染：从不改变选择、从不发码。状态机不在「等待选择」时，只会把浏览器带到当前应处的
/// 登录/同意页，或显示失效页。
#[get("/oauth/select-account")]
pub async fn select_account_page(
    req: HttpRequest,
    query: web::Query<TxnQuery>,
    oidc: Option<WebOidc>,
    db: WebDb,
) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    let Some(txn_id) = flow::parse_txn_id(query.txn.as_deref()) else {
        return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE);
    };
    let binding = cookie_value(&req, binding_cookie_name(oidc.secure_cookies()));
    let result = async {
        let Some((txn, client)) =
            store::find_live_transaction(&db, txn_id, binding.as_deref()).await?
        else {
            return Ok(None);
        };
        let session = flow::current_session(&db, sso_cookie_value(&req, &oidc).as_deref()).await?;
        let (step, session) = flow::evaluate(&db, &oidc, &txn, &client, session).await?;
        Ok::<_, crate::api::AppError>(Some((txn, client, step, session)))
    }
    .await;
    match result {
        Ok(Some((txn, client, flow::Step::SelectAccount, Some(current)))) => {
            render_select_account(&db, &txn, &client, &current, false).await
        }
        Ok(Some((txn, _, flow::Step::Login, _))) => {
            redirect(&format!("{PATH_LOGIN}?txn={}", txn.id)).finish()
        }
        Ok(Some((txn, _, flow::Step::Consent, _))) => {
            redirect(&format!("{PATH_CONSENT}?txn={}", txn.id)).finish()
        }
        Ok(_) => pages::error_page(400, flow::TXN_EXPIRED_MESSAGE),
        Err(_) => server_error_page(),
    }
}

/// POST /oauth/select-account（action = continue | other | cancel）
#[post("/oauth/select-account")]
pub async fn select_account_submit(
    req: HttpRequest,
    body: web::Bytes,
    oidc: Option<WebOidc>,
    db: WebDb,
    log: WebLog,
) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    if !is_form(&req) || !same_origin(&req, &oidc) {
        return pages::error_page(400, "请求来源无效。");
    }
    let form = parse_pairs(&body);
    let field = |name: &str| {
        form.single(name)
            .ok()
            .flatten()
            .unwrap_or_default()
            .to_string()
    };
    let Some(txn_id) = flow::parse_txn_id(Some(&field("txn"))) else {
        return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE);
    };
    let binding = cookie_value(&req, binding_cookie_name(oidc.secure_cookies()));
    let (txn, client) = match store::find_live_transaction(&db, txn_id, binding.as_deref()).await {
        Ok(Some(found)) => found,
        Ok(None) => return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE),
        Err(_) => return server_error_page(),
    };
    let csrf = field("csrf");
    if !store::csrf_matches(&txn, &csrf) {
        return pages::error_page(400, "页面已失效（CSRF 校验失败），请返回应用重新登录。");
    }

    match field("action").as_str() {
        "cancel" => {
            audit(
                &log,
                "INFO",
                "OIDC_ACCOUNT_SELECT_CANCEL",
                format!("取消为应用 {} 选择账号", client.client_id),
                json!({"client_id": client.client_id}),
                None,
                &req,
            );
            match flow::finish_with_error(
                &db,
                &oidc,
                &txn,
                OAuthError::access_denied("user cancelled account selection"),
            )
            .await
            {
                Ok(next) => respond(next, vec![]),
                Err(_) => server_error_page(),
            }
        }
        "other" => account_switch(&db, &log, &req, &txn, &client, &csrf).await,
        "continue" => {
            let session =
                match flow::current_session(&db, sso_cookie_value(&req, &oidc).as_deref()).await {
                    Ok(s) => flow::usable_session(&txn, s),
                    Err(_) => return server_error_page(),
                };
            let Some((session, user)) = session else {
                // 会话已过期/被撤销/用户被删除：不能免密继续，交给状态机（→ 登录页）。
                return match flow::advance(&db, &oidc, txn, &client, None).await {
                    Ok(next) => respond(next, vec![]),
                    Err(_) => server_error_page(),
                };
            };
            if txn.account_choice_session_id != Some(session.id) {
                // 展示后浏览器的登录账号变了（另一标签页切换/重新登录）：绝不悄悄选中新账号。
                return render_select_account(&db, &txn, &client, &(session, user), true).await;
            }
            let confirmed =
                match store::confirm_account_selection(&db, txn.id, session.id, user.id, &csrf)
                    .await
                {
                    Ok(Some(txn)) => txn,
                    // 并发/重复提交中落败，或事务刚好失效。
                    Ok(None) => return pages::error_page(400, flow::TXN_EXPIRED_MESSAGE),
                    Err(_) => return server_error_page(),
                };
            audit(
                &log,
                "INFO",
                "OIDC_ACCOUNT_SELECTED",
                format!("{} 确认以当前账号继续访问 {}", user.username, client.name),
                json!({"client_id": client.client_id}),
                Some(user.id),
                &req,
            );
            match flow::advance(&db, &oidc, confirmed, &client, Some((session, user))).await {
                Ok(next) => respond(next, vec![]),
                Err(_) => server_error_page(),
            }
        }
        _ => pages::error_page(400, "无效的操作。"),
    }
}

// ── Token 端点 ──────────────────────────────────────────────────────────────

fn token_error(err: &OAuthError, status: u16, basic_used: bool) -> HttpResponse {
    let mut builder = no_store(HttpResponse::build(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
    ));
    if status == 401 && basic_used {
        builder.insert_header((header::WWW_AUTHENTICATE, "Basic realm=\"floatctf\""));
    }
    builder.json(json!({ "error": err.error, "error_description": err.description }))
}

/// POST /oauth/token
#[post("/oauth/token")]
pub async fn token(
    req: HttpRequest,
    body: web::Bytes,
    oidc: Option<WebOidc>,
    db: WebDb,
    log: WebLog,
) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    if !is_form(&req) {
        return token_error(
            &OAuthError::invalid_request("content type must be application/x-www-form-urlencoded"),
            400,
            false,
        );
    }
    let params = parse_pairs(&body);
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let basic_used = auth_header.is_some();
    let (Ok(form_client_id), Ok(form_secret)) =
        (params.single("client_id"), params.single("client_secret"))
    else {
        return token_error(
            &OAuthError::invalid_request("duplicate client credentials"),
            400,
            basic_used,
        );
    };
    let presented = match client_auth::identify(auth_header, form_client_id, form_secret) {
        Ok(p) => p,
        Err(e) => {
            let status = if e.error == "invalid_client" {
                401
            } else {
                400
            };
            return token_error(&e, status, basic_used);
        }
    };

    // 限流：每个 client_id 每分钟 300 次，约束 secret / code 猜测（fail-closed）。
    match oidc
        .rate
        .hit(
            "oidc_token",
            &secret::sha256_hex(presented.client_id()),
            300,
            60,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return token_error(
                &OAuthError::temporarily_unavailable("rate limited"),
                429,
                basic_used,
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "OIDC token rate limiter unavailable (fail-closed)");
            return token_error(
                &OAuthError::temporarily_unavailable("temporarily unavailable"),
                503,
                basic_used,
            );
        }
    }

    let client = match flow::authenticate_client(&db, &presented).await {
        Ok(c) => c,
        Err(f) => return token_error(&f.error, f.status, basic_used),
    };
    match flow::exchange_code(&db, &oidc, &client, &params).await {
        Ok(resp) => {
            audit(
                &log,
                "INFO",
                "OIDC_TOKEN",
                format!("签发令牌给 {}", client.name),
                json!({"client_id": client.client_id, "scope": resp.scope}),
                None,
                &req,
            );
            no_store(HttpResponse::Ok()).json(resp)
        }
        Err(f) => {
            if f.error.error == "invalid_grant" {
                audit(
                    &log,
                    "WARN",
                    "OIDC_TOKEN_REJECTED",
                    format!("拒绝 {} 的授权码兑换", client.name),
                    json!({"client_id": client.client_id, "error": f.error.error, "reason": f.error.description}),
                    None,
                    &req,
                );
            }
            token_error(&f.error, f.status, basic_used)
        }
    }
}

// ── UserInfo ────────────────────────────────────────────────────────────────

fn bearer_challenge(error: Option<(&str, &str)>, status: StatusCode) -> HttpResponse {
    let value = match error {
        Some((code, desc)) => {
            format!("Bearer realm=\"floatctf\", error=\"{code}\", error_description=\"{desc}\"")
        }
        None => "Bearer realm=\"floatctf\"".to_string(),
    };
    let mut builder = no_store(HttpResponse::build(status));
    builder.insert_header((header::WWW_AUTHENTICATE, value));
    match error {
        Some((code, desc)) => builder.json(json!({"error": code, "error_description": desc})),
        None => builder.finish(),
    }
}

/// GET|POST /oauth/userinfo（OIDC Core §5.3：两种方法都必须支持）
#[route("/oauth/userinfo", method = "GET", method = "POST")]
pub async fn userinfo(
    req: HttpRequest,
    body: web::Bytes,
    oidc: Option<WebOidc>,
    db: WebDb,
) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    let header_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, value) = v.trim().split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| value.trim().to_string())
        });
    let has_auth_header = req.headers().contains_key(header::AUTHORIZATION);
    let body_token = if req.method() == actix_web::http::Method::POST && is_form(&req) {
        match parse_pairs(&body).single("access_token") {
            Ok(v) => v.map(str::to_string),
            Err(_) => {
                return bearer_challenge(
                    Some(("invalid_request", "duplicate access_token")),
                    StatusCode::BAD_REQUEST,
                );
            }
        }
    } else {
        None
    };
    let access_token = match (header_token, body_token, has_auth_header) {
        // RFC 6750 §2：一次请求只能用一种方式携带令牌。
        (Some(_), Some(_), _) | (None, Some(_), true) => {
            return bearer_challenge(
                Some(("invalid_request", "multiple token transmission methods")),
                StatusCode::BAD_REQUEST,
            );
        }
        (Some(t), None, _) | (None, Some(t), false) => t,
        (None, None, true) => {
            return bearer_challenge(
                Some(("invalid_token", "malformed authorization header")),
                StatusCode::UNAUTHORIZED,
            );
        }
        (None, None, false) => return bearer_challenge(None, StatusCode::UNAUTHORIZED),
    };
    match flow::userinfo(&db, &oidc, &access_token).await {
        Ok(Some(body)) => no_store(HttpResponse::Ok()).json(body),
        Ok(None) => bearer_challenge(
            Some((
                "invalid_token",
                "access token is invalid, expired or revoked",
            )),
            StatusCode::UNAUTHORIZED,
        ),
        Err(e) => {
            tracing::error!(error = %e, "OIDC userinfo failed");
            no_store(HttpResponse::InternalServerError()).json(json!({"error": "server_error"}))
        }
    }
}

// ── 登出（只清除 FloatCTF 本地 SSO 会话） ─────────────────────────────────────

/// POST /oauth/logout
#[post("/oauth/logout")]
pub async fn logout(req: HttpRequest, oidc: Option<WebOidc>, db: WebDb) -> HttpResponse {
    let Some(oidc) = oidc else {
        return not_enabled();
    };
    if !same_origin(&req, &oidc) {
        return HttpResponse::Forbidden().finish();
    }
    if let Some(value) = sso_cookie_value(&req, &oidc)
        && let Err(e) = store::revoke_session(&db, &value).await
    {
        tracing::error!(error = %e, "OIDC logout failed");
        return HttpResponse::InternalServerError().finish();
    }
    let mut resp = no_store(HttpResponse::NoContent()).finish();
    let _ = resp.add_cookie(&removal_cookie(
        sso_cookie_name(oidc.secure_cookies()),
        oidc.secure_cookies(),
    ));
    resp
}

#[cfg(test)]
mod tests {
    use super::same_origin_avatar;

    #[test]
    fn chooser_avatar_is_limited_to_same_origin_relative_paths() {
        assert_eq!(
            same_origin_avatar(Some("/public/avatars/a.png")).as_deref(),
            Some("/public/avatars/a.png")
        );
        for rejected in [
            "https://evil.example/a.png",
            "//evil.example/a.png",
            "/\\evil.example/a.png",
            "javascript:alert(1)",
            "data:image/png;base64,AAAA",
            "",
        ] {
            assert_eq!(same_origin_avatar(Some(rejected)), None, "{rejected}");
        }
        assert_eq!(same_origin_avatar(None), None);
    }
}
