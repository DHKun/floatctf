//! 服务端渲染的协议交互页（登录 / 同意 / 错误），与任何可插拔前端无关。
//!
//! minijinja 对 `.html` 模板默认 HTML 转义；所有动态值（应用名、用户名、state 等）都经转义输出。

use std::sync::OnceLock;

use actix_web::{HttpResponse, http::StatusCode};
use minijinja::Environment;
use serde::Serialize;

fn env() -> &'static Environment<'static> {
    static ENV: OnceLock<Environment<'static>> = OnceLock::new();
    ENV.get_or_init(|| {
        let mut env = Environment::new();
        for (name, source) in [
            ("layout.html", include_str!("../templates/layout.html")),
            ("login.html", include_str!("../templates/login.html")),
            ("consent.html", include_str!("../templates/consent.html")),
            ("error.html", include_str!("../templates/error.html")),
        ] {
            env.add_template(name, source)
                .expect("OIDC page template must compile");
        }
        env
    })
}

/// 渲染页面并附带安全响应头。
///
/// `form_target_origin`：表单提交后可能 302 去往的 RP origin。Chrome 对 `form-action`
/// 也校验重定向目标，因此必须把该 origin 加入白名单，否则授权完成后的跳转会被拦截。
pub fn html(
    status: StatusCode,
    template: &str,
    ctx: impl Serialize,
    form_target_origin: Option<&str>,
) -> HttpResponse {
    let body = match env().get_template(template).and_then(|t| t.render(ctx)) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error = %e, template, "OIDC page render failed");
            return HttpResponse::InternalServerError()
                .content_type("text/plain; charset=utf-8")
                .body("internal error");
        }
    };
    let form_action = match form_target_origin {
        Some(origin) => format!("'self' {origin}"),
        None => "'self'".to_string(),
    };
    HttpResponse::build(status)
        .content_type("text/html; charset=utf-8")
        .insert_header((
            "Content-Security-Policy",
            format!(
                "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; \
                 form-action {form_action}; frame-ancestors 'none'; base-uri 'none'"
            ),
        ))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        // 不能用 no-referrer：按 Fetch 规范，该策略会让浏览器在表单 POST 时发送 `Origin: null`，
        // 同源校验因此拒绝合法提交（真实浏览器 E2E 发现）。same-origin 仍不向 RP 泄露 Referer。
        .insert_header(("Referrer-Policy", "same-origin"))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"))
        .body(body)
}

pub fn error_page(status: u16, message: &str) -> HttpResponse {
    html(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
        "error.html",
        minijinja::context! { message => message },
        None,
    )
}

/// 同意页上的一项 scope。
#[derive(Debug, Serialize)]
pub struct ScopeItem {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub required: bool,
    pub checked: bool,
}

pub fn scope_item(name: &str, previously_granted: bool) -> Option<ScopeItem> {
    use super::super::domain::scope::{EMAIL, OPENID, PROFILE};
    match name {
        OPENID => Some(ScopeItem {
            name: OPENID,
            title: "账号标识",
            description: "一个稳定的匿名用户 ID，用于让应用识别你是同一个人。",
            required: true,
            checked: true,
        }),
        PROFILE => Some(ScopeItem {
            name: PROFILE,
            title: "基本资料",
            description: "用户名、昵称和头像。",
            required: false,
            checked: true,
        }),
        // 不默认分享邮箱：除非此前已授权过。
        EMAIL => Some(ScopeItem {
            name: EMAIL,
            title: "邮箱地址",
            description: "你在 FloatCTF 登记的邮箱（平台未做邮箱验证，应用会看到 email_verified=false）。",
            required: false,
            checked: previously_granted,
        }),
        _ => None,
    }
}

/// 回调地址的 origin（用于 CSP form-action）与展示用主机名。
pub fn origin_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .map(|u| u.origin().ascii_serialization())
        .filter(|o| o != "null")
}

pub fn host_of(url: Option<&str>) -> Option<String> {
    url.and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_escape_untrusted_values() {
        let resp_body = env()
            .get_template("error.html")
            .unwrap()
            .render(minijinja::context! { message => "<script>alert(1)</script>" })
            .unwrap();
        assert!(!resp_body.contains("<script>alert(1)</script>"));
        assert!(resp_body.contains("&lt;script&gt;"));
    }

    #[test]
    fn layout_does_not_force_null_origin_on_form_posts() {
        let layout = include_str!("../templates/layout.html");
        assert!(!layout.contains("no-referrer"));
        assert!(layout.contains(r#"<meta name="referrer" content="same-origin">"#));
    }

    #[test]
    fn email_not_preselected_unless_previously_granted() {
        assert!(!scope_item("email", false).unwrap().checked);
        assert!(scope_item("email", true).unwrap().checked);
        assert!(scope_item("openid", false).unwrap().required);
        assert!(scope_item("address", false).is_none());
    }

    #[test]
    fn csp_allows_only_self_and_rp_origin_for_forms() {
        let resp = html(
            StatusCode::OK,
            "error.html",
            minijinja::context! { message => "x" },
            Some("https://rp.example.com"),
        );
        let csp = resp
            .headers()
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("form-action 'self' https://rp.example.com;"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("script-src"));
        // 回归：no-referrer 会让浏览器表单 POST 带 `Origin: null`，导致同源校验误拒。
        assert_eq!(
            resp.headers().get("Referrer-Policy").unwrap(),
            "same-origin"
        );
        assert_eq!(
            origin_of("https://rp.example.com:8443/cb?x=1").unwrap(),
            "https://rp.example.com:8443"
        );
    }
}
