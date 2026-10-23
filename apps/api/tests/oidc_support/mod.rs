//! OIDC 集成测试支撑：真实 PostgreSQL（`DATABASE_URL`，不可达时 soft-skip，与其他 DB-gated 测试一致）
//! + 进程内 actix 服务（`configure_all_routes`，与生产同一路由聚合点）。
//!
//! 测试 key 是仓库内公开的测试专用 RSA key（`src/modules/identity/oidc/testdata/`）。

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use floatctf::core::config::{OidcConfig, OidcSigningKeyConfig};
use floatctf::modules::identity::oidc::{
    OidcProvider, RateGate,
    keys::{KeyMaterial, KeyRing},
};

pub const ISSUER: &str = "https://op.floatctf.test";

pub const TEST_KEY_A: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/modules/identity/oidc/testdata/test-key-a.pem"
));
pub const TEST_KEY_B: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/modules/identity/oidc/testdata/test-key-b.pem"
));

pub fn db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432/floatctf_db".into())
}

pub async fn connect_or_skip() -> Option<sea_orm::DatabaseConnection> {
    match sea_orm::Database::connect(&db_url()).await {
        Ok(db) => {
            // 迁移未应用（例如指向了旧库）时同样 skip，而不是误报失败。
            use sea_orm::ConnectionTrait;
            let ok = db
                .execute_unprepared("SELECT 1 FROM oidc_clients LIMIT 1")
                .await
                .is_ok();
            if ok {
                Some(db)
            } else {
                eprintln!("skip: oidc tables missing in {}", db_url());
                None
            }
        }
        Err(e) => {
            eprintln!("skip: DB unreachable ({e})");
            None
        }
    }
}

pub fn test_config() -> OidcConfig {
    OidcConfig {
        enabled: true,
        issuer: ISSUER.to_string(),
        signing_keys: vec![OidcSigningKeyConfig {
            kid: "test-a".into(),
            private_key_file: "unused".into(),
            active: true,
        }],
        session_ttl_secs: 8 * 3600,
        transaction_ttl_secs: 600,
        authorization_code_ttl_secs: 60,
        access_token_ttl_secs: 3600,
        id_token_ttl_secs: 3600,
        secret_rotation_grace_secs: 3600,
        allow_loopback_redirect_uris: true,
        require_client_approval: true,
    }
}

pub fn test_keys(active_b: bool) -> KeyRing {
    KeyRing::from_materials(vec![
        KeyMaterial {
            kid: "test-a".into(),
            pem: TEST_KEY_A.as_bytes().to_vec(),
            active: !active_b,
        },
        KeyMaterial {
            kid: "test-b".into(),
            pem: TEST_KEY_B.as_bytes().to_vec(),
            active: active_b,
        },
    ])
    .expect("test key ring")
}

/// 内存限流（测试专用）：与 Redis 实现同一语义（固定窗口内计数）。
#[derive(Default)]
pub struct MemoryGate {
    hits: Mutex<HashMap<String, u32>>,
}

#[async_trait::async_trait]
impl RateGate for MemoryGate {
    async fn hit(
        &self,
        bucket: &str,
        key: &str,
        limit: u32,
        _window_secs: u64,
    ) -> Result<bool, String> {
        let mut hits = self.hits.lock().unwrap();
        let n = hits.entry(format!("{bucket}:{key}")).or_insert(0);
        if *n >= limit {
            return Ok(false);
        }
        *n += 1;
        Ok(true)
    }
}

pub fn provider(config: OidcConfig, keys: KeyRing) -> OidcProvider {
    OidcProvider::new(config, keys, Arc::new(MemoryGate::default()))
}
