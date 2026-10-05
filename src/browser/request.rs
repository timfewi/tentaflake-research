//! Shared gate for browser-worker and service requests. The service must
//! reapply it: a worker message cannot authorize a destination, method or header.
use super::wire;
use crate::{
    config::ReadPostRule,
    error::{ErrorCode, Result},
    policy::{
        PublicUrl, limited_referrer, read_post_allowed, read_post_preflight_allowed,
        validate_origin_header, validate_read_preflight,
    },
};
use base64::Engine;
use chromiumoxide::cdp::browser_protocol::network;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use std::collections::HashSet;

pub const MAX_BODY: usize = 64 * 1024;
/// A CORS preflight response carries only headers; its body is capped tightly.
pub const MAX_PREFLIGHT_RESPONSE_BYTES: u64 = 8192;
const MAX_HEADERS: usize = 16 * 1024;

pub struct CheckedRequest {
    pub target: PublicUrl,
    pub method: Method,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

fn decode(body: &str) -> Result<Vec<u8>> {
    if body.len() > MAX_BODY.div_ceil(3) * 4 {
        return Err(ErrorCode::SizeLimit);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    if bytes.len() > MAX_BODY {
        return Err(ErrorCode::SizeLimit);
    }
    Ok(bytes)
}

pub fn check(request: &wire::HttpRequest, rules: &[ReadPostRule]) -> Result<CheckedRequest> {
    let target = PublicUrl::parse(&request.url)?;
    // The real pinned Chromium includes HeadlessChrome in its network and JS
    // identity. A worker may report that value but cannot choose another one.
    let browser_agent = crate::config::DEFAULT_USER_AGENT.replacen("Chrome/", "HeadlessChrome/", 1);
    if request.headers.len() > 64 || request.resource_type.len() > 32 {
        return Err(ErrorCode::SizeLimit);
    }
    let mut seen = HashSet::new();
    let mut headers = HeaderMap::new();
    let mut size = 0;
    for (name, value) in &request.headers {
        size += name.len() + value.len();
        if size > MAX_HEADERS {
            return Err(ErrorCode::SizeLimit);
        }
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| ErrorCode::InvalidRequest)?;
        let value = HeaderValue::from_str(value).map_err(|_| ErrorCode::InvalidRequest)?;
        if !seen.insert(name.clone()) {
            return Err(ErrorCode::InvalidRequest);
        }
        if matches!(name.as_str(), "authorization" | "proxy-authorization") {
            return Err(ErrorCode::PolicyDenied);
        }
        if name == "user-agent" && value.as_bytes() != browser_agent.as_bytes() {
            return Err(ErrorCode::PolicyDenied);
        }
        // The transport derives Host/framing from the checked URL and body.
        // Browser cache/client hints and arbitrary page headers confer no
        // authority and are not forwarded to the service's protected client.
        if matches!(
            name.as_str(),
            "accept"
                | "accept-language"
                | "content-type"
                | "cookie"
                | "origin"
                | "referer"
                | "user-agent"
                | "range"
                | "access-control-request-method"
                | "access-control-request-headers"
        ) {
            if name == "referer" {
                // A preflight carries no credentials and does not need the
                // source page URL to ask about a reviewed POST target.
                if request.method == "OPTIONS" {
                    continue;
                }
                let raw = value.to_str().map_err(|_| ErrorCode::InvalidRequest)?;
                if let Some(forwarded) = limited_referrer(raw, &target)? {
                    headers.insert(
                        name,
                        HeaderValue::from_str(&forwarded).map_err(|_| ErrorCode::InvalidRequest)?,
                    );
                }
                continue;
            }
            if name == "origin" {
                validate_origin_header(value.to_str().map_err(|_| ErrorCode::InvalidRequest)?)?;
            }
            headers.insert(name, value);
        }
    }
    headers.insert(
        "user-agent",
        HeaderValue::from_str(&browser_agent).map_err(|_| ErrorCode::InvalidRequest)?,
    );
    let body = decode(&request.body_base64)?;
    let method = match request.method.as_str() {
        "GET" if body.is_empty() => Method::GET,
        "HEAD" if body.is_empty() => Method::HEAD,
        "OPTIONS"
            if body.is_empty()
                && read_post_preflight_allowed(rules, &target)
                && headers.keys().all(|name| {
                    matches!(
                        name.as_str(),
                        "origin"
                            | "access-control-request-method"
                            | "access-control-request-headers"
                            | "accept"
                            | "accept-language"
                            | "user-agent"
                    )
                }) =>
        {
            validate_read_preflight(
                headers.get("origin").and_then(|value| value.to_str().ok()),
                headers
                    .get("access-control-request-method")
                    .and_then(|value| value.to_str().ok()),
                headers
                    .get("access-control-request-headers")
                    .and_then(|value| value.to_str().ok()),
            )?;
            Method::OPTIONS
        }
        "POST"
            if read_post_allowed(
                rules,
                &target,
                headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or(""),
                &body,
            ) =>
        {
            Method::POST
        }
        _ => return Err(ErrorCode::PolicyDenied),
    };
    if method != Method::OPTIONS
        && (headers.contains_key("access-control-request-method")
            || headers.contains_key("access-control-request-headers"))
    {
        return Err(ErrorCode::PolicyDenied);
    }
    Ok(CheckedRequest {
        target,
        method,
        headers,
        body,
    })
}

/// Preserve the gate while distinguishing its safe failure reasons at the
/// worker/service boundary. Header values themselves never enter diagnostics.
pub fn check_diagnosed(
    request: &wire::HttpRequest,
    rules: &[ReadPostRule],
) -> Result<CheckedRequest> {
    check(request, rules).map_err(|error| {
        if error != ErrorCode::PolicyDenied {
            return error;
        }
        let browser_agent =
            crate::config::DEFAULT_USER_AGENT.replacen("Chrome/", "HeadlessChrome/", 1);
        if request
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("user-agent") && value != &browser_agent)
        {
            ErrorCode::BrowserIdentityMismatch
        } else {
            ErrorCode::BrowserRequestDenied
        }
    })
}

pub fn from_cdp(
    request: &network::Request,
    resource_type: &str,
    main_document: bool,
    redirects: u32,
) -> Result<wire::HttpRequest> {
    if request.trust_token_params.is_some() {
        return Err(ErrorCode::PolicyDenied);
    }
    let object = request
        .headers
        .inner()
        .as_object()
        .ok_or(ErrorCode::InvalidResponse)?;
    if object.len() > 64 {
        return Err(ErrorCode::SizeLimit);
    }
    let headers = object
        .iter()
        .map(|(name, value)| {
            Ok((
                name.clone(),
                value.as_str().ok_or(ErrorCode::InvalidResponse)?.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut body = Vec::new();
    if let Some(entries) = &request.post_data_entries {
        if entries.len() > 64 {
            return Err(ErrorCode::SizeLimit);
        }
        for entry in entries {
            // Missing bytes can denote a file/blob or truncated POST data.
            // Never ask Chromium to read an external file to reconstruct it.
            let entry = entry.bytes.as_ref().ok_or(ErrorCode::PolicyDenied)?;
            let bytes = decode(entry.as_ref())?;
            if body.len() + bytes.len() > MAX_BODY {
                return Err(ErrorCode::SizeLimit);
            }
            body.extend_from_slice(&bytes);
        }
    }
    if request.has_post_data == Some(true) && body.is_empty() {
        return Err(ErrorCode::PolicyDenied);
    }
    if request.has_post_data == Some(false) && !body.is_empty() {
        return Err(ErrorCode::InvalidResponse);
    }
    Ok(wire::HttpRequest {
        url: request.url.clone(),
        method: request.method.clone(),
        headers,
        body_base64: base64::engine::general_purpose::STANDARD.encode(body),
        resource_type: resource_type.to_owned(),
        main_document,
        redirects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnosed_gate_keeps_denials_and_never_echoes_header_values() {
        let mut request = post(b"");
        request.method = "GET".into();
        request.headers = vec![("User-Agent".into(), "untrusted-secret-value".into())];
        let error = check_diagnosed(&request, &[]).err().unwrap();
        assert_eq!(error, ErrorCode::BrowserIdentityMismatch);
        let failure = crate::error::ToolFailure::from(error);
        assert_eq!(failure.code, ErrorCode::PolicyDenied);
        let json = serde_json::to_string(&failure).unwrap();
        assert!(json.contains("browser_identity_mismatch"));
        assert!(!json.contains("untrusted-secret-value"));
        request.headers = vec![("Authorization".into(), "untrusted-secret-value".into())];
        assert!(matches!(
            check_diagnosed(&request, &[]),
            Err(ErrorCode::BrowserRequestDenied)
        ));
        request.headers.clear();
        assert!(check_diagnosed(&request, &[]).is_ok());
    }
    use crate::{config::ReadPostOperation, policy::sha256};
    use serde_json::json;

    fn post(body: &[u8]) -> wire::HttpRequest {
        wire::HttpRequest {
            url: "https://example.com/read".into(),
            method: "POST".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body_base64: base64::engine::general_purpose::STANDARD.encode(body),
            resource_type: "Fetch".into(),
            main_document: false,
            redirects: 0,
        }
    }

    #[test]
    fn post_requires_exact_operator_recipe_and_never_accepts_private_targets() {
        let body = br#"{"query":"article"}"#;
        let rules = [ReadPostRule {
            origin: "https://example.com".into(),
            path: "/read".into(),
            max_bytes: 128,
            operation: ReadPostOperation::ExactBody {
                sha256: sha256(body),
                content_type: "application/json".into(),
            },
        }];
        assert!(matches!(
            check(&post(body), &[]),
            Err(ErrorCode::PolicyDenied)
        ));
        assert_eq!(check(&post(body), &rules).unwrap().method, Method::POST);
        assert!(matches!(
            check(&post(br#"{"mutation":"buy"}"#), &rules),
            Err(ErrorCode::PolicyDenied)
        ));
        for url in [
            "http://127.0.0.1/read",
            "http://[::1]/read",
            "http://169.254.169.254/read",
        ] {
            let mut request = post(body);
            request.url = url.into();
            assert!(matches!(
                check(&request, &rules),
                Err(ErrorCode::DestinationDenied)
            ));
        }
        for url in [
            "https://example.com/read?override=true",
            "https://example.org/read",
            "https://example.com/write",
        ] {
            let mut request = post(body);
            request.url = url.into();
            assert!(matches!(
                check(&request, &rules),
                Err(ErrorCode::PolicyDenied)
            ));
        }
    }

    #[test]
    fn real_cors_preflight_is_limited_to_a_granted_read_post() {
        let body = br#"{"query":"article"}"#;
        let rules = [ReadPostRule {
            origin: "https://example.com".into(),
            path: "/read".into(),
            max_bytes: 128,
            operation: ReadPostOperation::ExactBody {
                sha256: sha256(body),
                content_type: "application/json".into(),
            },
        }];
        let mut request = post(b"");
        request.method = "OPTIONS".into();
        request.headers = vec![
            ("Origin".into(), "https://source.example".into()),
            ("Access-Control-Request-Method".into(), "POST".into()),
            (
                "Access-Control-Request-Headers".into(),
                "content-type".into(),
            ),
        ];
        assert_eq!(check(&request, &rules).unwrap().method, Method::OPTIONS);
        assert!(matches!(check(&request, &[]), Err(ErrorCode::PolicyDenied)));
        request.url = "https://example.com/read?other=1".into();
        assert!(matches!(
            check(&request, &rules),
            Err(ErrorCode::PolicyDenied)
        ));
        request.url = "https://example.com/read".into();
        for (name, value) in [
            ("Access-Control-Request-Method", "GET"),
            ("Access-Control-Request-Headers", "authorization"),
            ("Origin", "https://source.example/private"),
        ] {
            let saved = request.headers.clone();
            request
                .headers
                .iter_mut()
                .find(|(key, _)| key == name)
                .unwrap()
                .1 = value.into();
            assert!(check(&request, &rules).is_err());
            request.headers = saved;
        }
        request
            .headers
            .push(("Cookie".into(), "session=private".into()));
        assert!(matches!(
            check(&request, &rules),
            Err(ErrorCode::PolicyDenied)
        ));
        request.headers.pop();
        request.body_base64 = base64::engine::general_purpose::STANDARD.encode(body);
        assert!(matches!(
            check(&request, &rules),
            Err(ErrorCode::PolicyDenied)
        ));
        request.body_base64.clear();
        request.method = "GET".into();
        assert!(matches!(
            check(&request, &rules),
            Err(ErrorCode::PolicyDenied)
        ));
    }

    #[test]
    fn request_framing_credentials_duplicates_and_body_limits_are_checked() {
        let mut request = post(b"");
        request.method = "GET".into();
        request.headers = vec![
            ("Host".into(), "private.internal".into()),
            ("Connection".into(), "upgrade".into()),
            ("Cookie".into(), "session=ephemeral".into()),
        ];
        let checked = check(&request, &[]).unwrap();
        assert_eq!(checked.headers.len(), 2);
        assert_eq!(checked.headers["cookie"], "session=ephemeral");
        request.headers.push((
            "Authorization".into(),
            "Bearer must-not-be-forwarded".into(),
        ));
        assert!(matches!(check(&request, &[]), Err(ErrorCode::PolicyDenied)));
        request.headers = vec![
            ("Content-Type".into(), "a".into()),
            ("content-type".into(), "b".into()),
        ];
        assert!(matches!(
            check(&request, &[]),
            Err(ErrorCode::InvalidRequest)
        ));
        request.headers = vec![("Cookie".into(), "x\r\nInjected: yes".into())];
        assert!(matches!(
            check(&request, &[]),
            Err(ErrorCode::InvalidRequest)
        ));
        request.headers.clear();
        request.body_base64 =
            base64::engine::general_purpose::STANDARD.encode(vec![0; MAX_BODY + 1]);
        assert!(matches!(check(&request, &[]), Err(ErrorCode::SizeLimit)));
        request.body_base64 = base64::engine::general_purpose::STANDARD.encode(b"GET body");
        assert!(matches!(check(&request, &[]), Err(ErrorCode::PolicyDenied)));
    }

    #[test]
    fn cache_validators_are_stripped_from_browser_requests() {
        let mut request = post(b"");
        request.method = "GET".into();
        request.headers = vec![
            ("If-None-Match".into(), "\"session-tag\"".into()),
            (
                "If-Modified-Since".into(),
                "Tue, 01 Jan 2030 00:00:00 GMT".into(),
            ),
            ("Range".into(), "bytes=0-9".into()),
        ];
        let checked = check(&request, &[]).unwrap();
        assert!(!checked.headers.contains_key("if-none-match"));
        assert!(!checked.headers.contains_key("if-modified-since"));
        assert_eq!(checked.headers["range"], "bytes=0-9");
    }

    #[test]
    fn browser_user_agent_must_match_the_pinned_chromium_profile() {
        let mut request = post(b"");
        request.method = "GET".into();
        request.headers = vec![("User-Agent".into(), "Unique-Worker-Tag".into())];
        assert!(matches!(check(&request, &[]), Err(ErrorCode::PolicyDenied)));

        request.headers.clear();
        let checked = check(&request, &[]).unwrap();
        let expected = crate::config::DEFAULT_USER_AGENT.replacen("Chrome/", "HeadlessChrome/", 1);
        assert_eq!(checked.headers["user-agent"], expected);
    }

    #[test]
    fn referrer_never_exposes_cross_origin_path_or_downgrades_https() {
        let mut request = post(b"");
        request.method = "GET".into();
        request.url = "https://destination.example/resource".into();
        request.headers = vec![(
            "Referer".into(),
            "https://source.example/private?token=secret#fragment".into(),
        )];
        let checked = check(&request, &[]).unwrap();
        assert_eq!(checked.headers["referer"], "https://source.example/");

        request.headers[0].1 = "https://destination.example/private?token=secret#fragment".into();
        let checked = check(&request, &[]).unwrap();
        assert_eq!(
            checked.headers["referer"],
            "https://destination.example/private?token=secret"
        );

        request.url = "http://destination.example/resource".into();
        request.headers[0].1 = "https://source.example/private?token=secret".into();
        let checked = check(&request, &[]).unwrap();
        assert!(!checked.headers.contains_key("referer"));
    }

    #[test]
    fn origin_header_cannot_carry_a_path_or_query() {
        let mut request = post(b"");
        request.method = "GET".into();
        request.headers = vec![(
            "Origin".into(),
            "https://source.example/private?token=secret".into(),
        )];
        assert!(matches!(
            check(&request, &[]),
            Err(ErrorCode::InvalidRequest)
        ));
        request.headers[0].1 = "https://source.example".into();
        assert_eq!(
            check(&request, &[]).unwrap().headers["origin"],
            "https://source.example"
        );
        request.headers[0].1 = "null".into();
        assert_eq!(check(&request, &[]).unwrap().headers["origin"], "null");
    }

    #[test]
    fn omitted_or_file_backed_cdp_post_data_is_not_reconstructed() {
        let base = json!({"url":"https://example.com/read", "method":"POST", "headers":{}, "hasPostData":true,
            "initialPriority":"High", "referrerPolicy":"no-referrer"});
        for entries in [json!(null), json!([{}])] {
            let mut value = base.clone();
            value["postDataEntries"] = entries;
            let request: network::Request = serde_json::from_value(value).unwrap();
            assert!(matches!(
                from_cdp(&request, "Fetch", false, 0),
                Err(ErrorCode::PolicyDenied)
            ));
        }
        let mut value = base;
        value["postDataEntries"] = json!([{"bytes":"YWJj"}, {"bytes":"ZGVm"}]);
        let request: network::Request = serde_json::from_value(value).unwrap();
        let copied = from_cdp(&request, "Fetch", false, 0).unwrap();
        assert_eq!(decode(&copied.body_base64).unwrap(), b"abcdef");
    }
}
