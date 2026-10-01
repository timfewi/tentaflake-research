//! Private, bounded worker IPC. Body files use numeric IDs authorized for a
//! pending session request; neither endpoint accepts a page/model-supplied path.

use crate::{api::ScrollDirection, error::ErrorCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    Action {
        id: u64,
        action: Action,
    },
    Http {
        id: u64,
        result: Result<HttpReply, ErrorCode>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Open { url: String },
    Read,
    FollowLink { reference: String },
    Expand { reference: String },
    Scroll { direction: ScrollDirection },
    Close,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Output {
    Ready {
        version: u32,
    },
    Http {
        id: u64,
        request: HttpRequest,
    },
    /// Acknowledges each HTTP result, including errors without a body file.
    Consumed {
        id: u64,
    },
    CancelHttp {
        id: u64,
    },
    Stopped {
        code: ErrorCode,
    },
    Completed {
        id: u64,
        result: Result<Option<Snapshot>, ErrorCode>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    /// Base64 permits exact non-UTF8 bodies, with a 64 KiB decoded cap.
    pub body_base64: String,
    pub resource_type: String,
    pub main_document: bool,
    pub redirects: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_bytes: u64,
    pub body_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: Uuid,
    pub url: String,
    pub title: String,
    pub html_bytes: u64,
    pub html_sha256: String,
    pub references: Vec<Reference>,
    pub truncated_references: bool,
    pub pending_requests: bool,
    pub request_errors: Vec<ErrorCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub reference: String,
    pub kind: ReferenceKind,
    pub label: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    Link,
    Expand,
}

impl Snapshot {
    /// Reapply at the service boundary before reading the worker's HTML file or
    /// exposing references. The HTML remains untrusted even with a valid hash.
    pub fn validate(&self, maximum: u64) -> crate::error::Result<()> {
        use crate::{error::ErrorCode, policy::PublicUrl};
        if maximum > super::body::MAX_BYTES
            || self.html_bytes > maximum
            || self.title.len() > 4096
            || self.references.len() > 128
            || self.request_errors.len() > 64
        {
            return Err(ErrorCode::SizeLimit);
        }
        PublicUrl::parse(&self.url)?;
        if !digest_valid(&self.html_sha256) {
            return Err(ErrorCode::InvalidResponse);
        }
        let mut seen = std::collections::HashSet::new();
        for reference in &self.references {
            let (version, index) = reference
                .reference
                .split_once(':')
                .ok_or(ErrorCode::InvalidResponse)?;
            let index: usize = index.parse().map_err(|_| ErrorCode::InvalidResponse)?;
            if index >= 128
                || version != self.version.to_string()
                || reference.reference != format!("{}:{index}", self.version)
                || !seen.insert(index)
                || reference.label.len() > 512
            {
                return Err(ErrorCode::InvalidResponse);
            }
            match reference.kind {
                ReferenceKind::Link => {
                    PublicUrl::parse(reference.url.as_deref().ok_or(ErrorCode::InvalidResponse)?)?;
                }
                ReferenceKind::Expand if reference.url.is_none() => (),
                ReferenceKind::Expand => return Err(ErrorCode::InvalidResponse),
            }
        }
        Ok(())
    }
}

pub(super) fn digest_valid(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl HttpReply {
    /// HTTP entities have already been decoded by the protected transport.
    /// Preserve end-to-end headers, including multiple Set-Cookie/CSP fields,
    /// while removing hop framing, compressed lengths and alternative routes.
    pub fn from_response(
        response: &crate::http::HttpResponse,
        maximum: u64,
    ) -> crate::error::Result<Self> {
        use crate::error::ErrorCode;
        let mut excluded: std::collections::HashSet<String> = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "content-length",
            "content-encoding",
            "alt-svc",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        for header in response.headers.get_all("connection") {
            for token in header
                .to_str()
                .map_err(|_| ErrorCode::InvalidResponse)?
                .split(',')
            {
                let name = http::HeaderName::from_bytes(token.trim().as_bytes())
                    .map_err(|_| ErrorCode::InvalidResponse)?;
                excluded.insert(name.to_string());
            }
        }
        let headers = response
            .headers
            .iter()
            .filter(|(name, _)| !excluded.contains(name.as_str()))
            .map(|(name, value)| {
                Ok((
                    name.to_string(),
                    value
                        .to_str()
                        .map_err(|_| ErrorCode::InvalidResponse)?
                        .to_owned(),
                ))
            })
            .collect::<crate::error::Result<Vec<_>>>()?;
        let reply = Self {
            status: response.status,
            headers,
            body_bytes: response.body.len() as u64,
            body_sha256: crate::policy::sha256(&response.body),
        };
        reply.validate(maximum)?;
        Ok(reply)
    }

    pub fn validate(&self, maximum: u64) -> crate::error::Result<()> {
        use crate::error::ErrorCode;
        if maximum > super::body::MAX_BYTES
            || self.body_bytes > maximum
            || self.headers.len() > 128
            || self
                .headers
                .iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>()
                > 64 * 1024
        {
            return Err(ErrorCode::SizeLimit);
        }
        if !(200..=599).contains(&self.status)
            || !digest_valid(&self.body_sha256)
            || (matches!(self.status, 204 | 205 | 304) && self.body_bytes != 0)
        {
            return Err(ErrorCode::InvalidResponse);
        }
        for (name, value) in &self.headers {
            let name = http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ErrorCode::InvalidResponse)?;
            http::HeaderValue::from_str(value).map_err(|_| ErrorCode::InvalidResponse)?;
            if matches!(
                name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
                    | "content-length"
                    | "content-encoding"
                    | "alt-svc"
            ) {
                return Err(ErrorCode::InvalidResponse);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::sha256;

    #[test]
    fn decoded_response_headers_preserve_policy_and_ephemeral_cookies() {
        let mut response = crate::http::HttpResponse {
            status: 200,
            headers: http::HeaderMap::new(),
            body: b"decoded".to_vec(),
        };
        for (name, value) in [
            ("content-encoding", "gzip"),
            ("content-length", "123"),
            ("connection", "X-Hop"),
            ("x-hop", "remove"),
            ("alt-svc", "h3=\":443\""),
            ("content-type", "text/html"),
            ("set-cookie", "a=1; Secure"),
            ("set-cookie", "b=2; Secure"),
            ("content-security-policy", "default-src 'self'"),
            ("content-security-policy", "object-src 'none'"),
        ] {
            response
                .headers
                .append(http::HeaderName::from_static(name), value.parse().unwrap());
        }
        let reply = HttpReply::from_response(&response, 1024).unwrap();
        assert_eq!(reply.body_bytes, 7);
        assert_eq!(reply.body_sha256, sha256(b"decoded"));
        assert_eq!(reply.headers.len(), 5);
        assert_eq!(
            reply
                .headers
                .iter()
                .filter(|(name, _)| name == "set-cookie")
                .count(),
            2
        );
        assert_eq!(
            reply
                .headers
                .iter()
                .filter(|(name, _)| name == "content-security-policy")
                .count(),
            2
        );
        response.status = 204;
        assert!(HttpReply::from_response(&response, 1024).is_err());
    }

    #[test]
    fn forged_reference_metadata_and_response_framing_are_rejected() {
        let version = Uuid::new_v4();
        let mut snapshot = Snapshot {
            version,
            url: "https://example.com/".into(),
            title: "Quote".into(),
            html_bytes: 1,
            html_sha256: sha256(b"x"),
            references: vec![Reference {
                reference: format!("{version}:3"),
                kind: ReferenceKind::Link,
                label: "Next".into(),
                url: Some("https://example.com/next".into()),
            }],
            truncated_references: false,
            pending_requests: true,
            request_errors: vec![],
        };
        snapshot.validate(1024).unwrap();
        snapshot.references[0].reference = format!("{version}:03");
        assert!(snapshot.validate(1024).is_err());
        snapshot.references[0].reference = format!("{version}:3");
        snapshot.references[0].url = Some("http://127.0.0.1/".into());
        assert!(snapshot.validate(1024).is_err());
        snapshot.references[0].url = None;
        snapshot.references[0].kind = ReferenceKind::Expand;
        snapshot.validate(1024).unwrap();
        snapshot.request_errors = vec![ErrorCode::PolicyDenied; 65];
        assert!(snapshot.validate(1024).is_err());
        let mut reply = HttpReply {
            status: 200,
            headers: vec![],
            body_bytes: 0,
            body_sha256: sha256(b""),
        };
        reply.validate(0).unwrap();
        for (name, value) in [
            ("Content-Length", "0"),
            ("x-value", "bad\r\nheader"),
            ("Alt-Svc", "h3=\":443\""),
        ] {
            reply.headers = vec![(name.into(), value.into())];
            assert!(reply.validate(1024).is_err());
        }
    }
}
