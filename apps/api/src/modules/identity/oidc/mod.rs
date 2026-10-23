//! FloatCTF 作为通用 OpenID Connect Provider（OP）。
//!
//! 设计决策见 `docs/identity/ADR-oidc-provider.md`。分层：
//! - `domain/`：纯协议逻辑（参数校验、PKCE、scope、claims、元数据），无 I/O；
//! - `keys`：RS256 key ring 与 JWKS；
//! - `api/`：HTTP 端点（协议端点挂在根路径，管理接口挂在 `/api/oidc`、`/api/admin/oidc`）。
//!
//! `[oidc].enabled = false` 时不注册 [`OidcProvider`]，所有协议端点返回 404，
//! 平台其余行为与未引入本模块时逐字一致。

pub mod api;
pub mod clients;
pub mod domain;
pub mod keys;

use std::sync::Arc;

use actix_web::web::{self, ServiceConfig};

use crate::core::config::OidcConfig;
use crate::infrastructure::ratelimit::RateLimiter;
use keys::KeyRing;

/// 限流抽象：生产实现是 Redis 共享滑动窗口（fail-closed）；测试可注入内存实现。
#[async_trait::async_trait]
pub trait RateGate: Send + Sync {
    /// 记录一次访问并返回是否仍在配额内；后端故障返回 `Err`，调用方必须拒绝请求。
    async fn hit(
        &self,
        bucket: &str,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> Result<bool, String>;
}

#[async_trait::async_trait]
impl RateGate for RateLimiter {
    async fn hit(
        &self,
        bucket: &str,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> Result<bool, String> {
        self.hit_window(bucket, key, limit, window_secs).await
    }
}

/// 进程级 OP 运行时（仅在 `enabled = true` 且 key ring 加载成功时存在）。
pub struct OidcProvider {
    pub config: OidcConfig,
    pub keys: KeyRing,
    pub rate: Arc<dyn RateGate>,
}

impl OidcProvider {
    pub fn new(config: OidcConfig, keys: KeyRing, rate: Arc<dyn RateGate>) -> Self {
        Self { config, keys, rate }
    }

    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// issuer 为 https 时 Cookie 使用 `__Host-` 前缀并带 `Secure`。
    pub fn secure_cookies(&self) -> bool {
        self.config.issuer.starts_with("https://")
    }
}

pub type WebOidc = web::Data<OidcProvider>;

/// 协议端点（根路径）：Discovery / JWKS / authorize / login / consent / token / userinfo / logout。
pub fn configure_protocol_routes(cfg: &mut ServiceConfig) {
    cfg.service(api::discovery::openid_configuration)
        .service(api::discovery::oauth_authorization_server)
        .service(api::discovery::jwks);
}

/// 浏览器端 RP 需要跨域访问、且不读取 Cookie 的协议路径（CORS 对任意 Origin 开放）。
pub fn is_public_cors_path(path: &str) -> bool {
    use domain::metadata::*;
    matches!(
        path,
        PATH_DISCOVERY | PATH_AS_METADATA | PATH_JWKS | PATH_TOKEN | PATH_USERINFO
    )
}
