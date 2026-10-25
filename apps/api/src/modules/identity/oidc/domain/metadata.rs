//! OP 元数据（OIDC Discovery 1.0 §3 / RFC 8414 §2）。
//!
//! **只宣告已实现且经测试的能力**。路径与 `bootstrap/routes.rs` 注册的协议路由一一对应。

use serde_json::{Value, json};

pub const PATH_DISCOVERY: &str = "/.well-known/openid-configuration";
pub const PATH_AS_METADATA: &str = "/.well-known/oauth-authorization-server";
pub const PATH_JWKS: &str = "/.well-known/jwks.json";
pub const PATH_AUTHORIZE: &str = "/oauth/authorize";
pub const PATH_LOGIN: &str = "/oauth/login";
pub const PATH_CONSENT: &str = "/oauth/consent";
pub const PATH_SELECT_ACCOUNT: &str = "/oauth/select-account";
pub const PATH_TOKEN: &str = "/oauth/token";
pub const PATH_USERINFO: &str = "/oauth/userinfo";
pub const PATH_LOGOUT: &str = "/oauth/logout";

/// 已支持的 claims（`sub` 与 ID Token 注册 claims + scope claims）。
pub const CLAIMS_SUPPORTED: [&str; 16] = [
    "iss",
    "sub",
    "aud",
    "azp",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "at_hash",
    "preferred_username",
    "nickname",
    "name",
    "picture",
    "updated_at",
    "email",
    "email_verified",
];

/// OIDC Discovery 文档。
pub fn openid_configuration(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}{PATH_AUTHORIZE}"),
        "token_endpoint": format!("{issuer}{PATH_TOKEN}"),
        "userinfo_endpoint": format!("{issuer}{PATH_USERINFO}"),
        "jwks_uri": format!("{issuer}{PATH_JWKS}"),
        "scopes_supported": super::scope::SUPPORTED,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": [super::pkce::METHOD_S256],
        "claims_supported": CLAIMS_SUPPORTED,
        "claims_parameter_supported": false,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "require_request_uri_registration": false,
        "authorization_response_iss_parameter_supported": true,
    })
}

/// RFC 8414 授权服务器元数据（与 Discovery 同源同值）。
pub fn oauth_authorization_server(issuer: &str) -> Value {
    openid_configuration(issuer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_endpoints_share_the_exact_issuer() {
        let issuer = "https://ctf.example.com";
        let doc = openid_configuration(issuer);
        assert_eq!(doc["issuer"], issuer);
        for key in [
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ] {
            let url = doc[key].as_str().unwrap();
            assert!(url.starts_with(&format!("{issuer}/")), "{key}={url}");
        }
        assert_eq!(
            doc["jwks_uri"],
            "https://ctf.example.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn discovery_only_declares_implemented_capabilities() {
        let doc = openid_configuration("https://x.example");
        assert_eq!(doc["response_types_supported"], json!(["code"]));
        assert_eq!(doc["grant_types_supported"], json!(["authorization_code"]));
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            doc["id_token_signing_alg_values_supported"],
            json!(["RS256"])
        );
        // 默认值为 true 的可选能力必须显式否认（Discovery §3）。
        assert_eq!(doc["request_uri_parameter_supported"], false);
        // 未实现的端点不得出现。
        for absent in [
            "registration_endpoint",
            "end_session_endpoint",
            "revocation_endpoint",
            "introspection_endpoint",
            "check_session_iframe",
        ] {
            assert!(doc.get(absent).is_none(), "{absent}");
        }
        let methods = doc["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap();
        assert!(
            !methods
                .iter()
                .any(|m| m == "private_key_jwt" || m == "client_secret_jwt")
        );
    }
}
