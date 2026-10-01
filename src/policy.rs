use crate::config::{ReadPostOperation, ReadPostRule};
use crate::error::{ErrorCode, Result};
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Instant;
use url::{Host, Url};

static SPECIAL_NETWORKS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
        "::/96",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .iter()
    .map(|cidr| cidr.parse().expect("constant CIDR"))
    .collect()
});

pub fn public_ip(address: IpAddr, denied: &[IpNet]) -> bool {
    let allocated = match address {
        IpAddr::V4(_) => true,
        IpAddr::V6(ip) => ip.segments()[0] & 0xe000 == 0x2000,
    };
    allocated
        && !SPECIAL_NETWORKS
            .iter()
            .chain(denied)
            .any(|net| net.contains(&address))
}

/// Validates the whole DNS answer before returning any dialable address. The
/// caller must dial these numeric addresses, never resolve the hostname again.
pub fn public_addresses(addresses: Vec<SocketAddr>, denied: &[IpNet]) -> Result<Vec<SocketAddr>> {
    if addresses.is_empty()
        || addresses.len() > 64
        || addresses
            .iter()
            .any(|address| !public_ip(address.ip(), denied))
    {
        return Err(ErrorCode::DestinationDenied);
    }
    let mut seen = HashSet::new();
    Ok(addresses
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicUrl(Url);

impl PublicUrl {
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > 8192 || input.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'\\') {
            return Err(ErrorCode::DestinationDenied);
        }
        let parsed = Url::parse(input).map_err(|_| ErrorCode::DestinationDenied)?;
        let expected_port = match parsed.scheme() {
            "http" => 80,
            "https" => 443,
            _ => return Err(ErrorCode::DestinationDenied),
        };
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.port_or_known_default() != Some(expected_port)
            || input.split_once("://").is_none_or(|(_, rest)| {
                rest.split(['/', '?', '#'])
                    .next()
                    .unwrap_or("")
                    .contains('@')
            })
        {
            return Err(ErrorCode::DestinationDenied);
        }
        match parsed.host().ok_or(ErrorCode::DestinationDenied)? {
            Host::Ipv4(ip) if !public_ip(ip.into(), &[]) => {
                return Err(ErrorCode::DestinationDenied);
            }
            Host::Ipv6(ip) if !public_ip(ip.into(), &[]) => {
                return Err(ErrorCode::DestinationDenied);
            }
            Host::Domain(host) => {
                let host = host.trim_end_matches('.');
                if !host.contains('.')
                    || host.len() > 253
                    || [
                        "localhost",
                        "local",
                        "internal",
                        "lan",
                        "home.arpa",
                        "onion",
                        "ts.net",
                    ]
                    .iter()
                    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
                {
                    return Err(ErrorCode::DestinationDenied);
                }
            }
            _ => {}
        }
        Ok(Self(parsed))
    }

    pub fn url(&self) -> &Url {
        &self.0
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    pub fn origin(&self) -> String {
        self.0.origin().ascii_serialization()
    }
    pub fn host(&self) -> String {
        match self.0.host().expect("validated host") {
            Host::Domain(host) => host.trim_end_matches('.').to_owned(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        }
    }
    pub fn port(&self) -> u16 {
        self.0.port_or_known_default().expect("validated port")
    }
    pub fn request_url(&self) -> Url {
        let mut url = self.0.clone();
        url.set_fragment(None);
        url
    }
    pub fn without_fragment(&self) -> Self {
        Self(self.request_url())
    }
    pub fn redirect(&self, location: &str) -> Result<Self> {
        if location.bytes().any(|b| b <= 0x20 || b == b'\\') {
            return Err(ErrorCode::DestinationDenied);
        }
        let next = self
            .0
            .join(location)
            .map_err(|_| ErrorCode::DestinationDenied)?;
        Self::parse(next.as_str())
    }
}

/// Apply the minimum browser referrer policy even when a page or caller asks
/// for a more revealing header. Never add a referrer when none was supplied.
pub fn limited_referrer(value: &str, target: &PublicUrl) -> Result<Option<String>> {
    let source = PublicUrl::parse(value)?;
    if source.url().scheme() == "https" && target.url().scheme() == "http" {
        return Ok(None);
    }
    if source.origin() == target.origin() {
        Ok(Some(source.request_url().to_string()))
    } else {
        Ok(Some(format!("{}/", source.origin())))
    }
}

/// Accept only a serialized public origin or `null`, never a path or query.
pub fn validate_origin_header(value: &str) -> Result<()> {
    if value != "null" {
        let origin = PublicUrl::parse(value)?;
        if value != origin.origin() {
            return Err(ErrorCode::InvalidRequest);
        }
    }
    Ok(())
}

/// Only the header shape needed for an operator-approved JSON read POST may be
/// preflighted. This does not authorize the subsequent POST body.
pub fn validate_read_preflight(
    origin: Option<&str>,
    method: Option<&str>,
    requested_headers: Option<&str>,
) -> Result<()> {
    validate_origin_header(origin.ok_or(ErrorCode::PolicyDenied)?)?;
    if method != Some("POST") {
        return Err(ErrorCode::PolicyDenied);
    }
    if let Some(requested) = requested_headers
        && (requested.len() > 128
            || requested
                .split(',')
                .any(|name| !name.trim().eq_ignore_ascii_case("content-type")))
    {
        return Err(ErrorCode::PolicyDenied);
    }
    Ok(())
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// This is an operator-authored recipe, never permission inferred from a page's
/// description. A pinned GraphQL document cannot substitute a mutation/query.
pub fn read_post_allowed(
    rules: &[ReadPostRule],
    target: &PublicUrl,
    content_type: &str,
    body: &[u8],
) -> bool {
    rules.iter().any(|rule| {
        if !read_post_target_matches(rule, target) || body.len() > rule.max_bytes {
            return false;
        }
        match &rule.operation {
            ReadPostOperation::ExactBody {
                sha256: expected,
                content_type: expected_type,
            } => content_type == expected_type && sha256(body) == *expected,
            ReadPostOperation::Graphql {
                document_sha256,
                operation_name,
            } => {
                if content_type != "application/json" {
                    return false;
                }
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Request {
                    query: String,
                    #[serde(rename = "operationName")]
                    operation_name: String,
                    #[serde(default)]
                    variables: std::collections::BTreeMap<String, serde_json::Value>,
                }
                use serde::Deserialize;
                serde_json::from_slice::<Request>(body).is_ok_and(|request| {
                    request.operation_name == *operation_name
                        && sha256(request.query.as_bytes()) == *document_sha256
                        && request.variables.len() <= 64
                })
            }
        }
    })
}

fn read_post_target_matches(rule: &ReadPostRule, target: &PublicUrl) -> bool {
    target.origin() == rule.origin
        && target.url().path() == rule.path
        && target.url().query().is_none()
}

/// A CORS preflight can probe only a target already granted for a read POST.
/// The actual POST still needs its reviewed body and content type.
pub fn read_post_preflight_allowed(rules: &[ReadPostRule], target: &PublicUrl) -> bool {
    rules
        .iter()
        .any(|rule| read_post_target_matches(rule, target))
}

/// Credentials may only accompany provider pagination at the original exact
/// endpoint. Even a public URL on another origin is not a pagination capability.
pub struct PaginationGuard {
    endpoint: PublicUrl,
    seen: HashSet<String>,
    maximum: usize,
    remaining_items: usize,
    deadline: Instant,
}

impl PaginationGuard {
    pub fn new(endpoint: PublicUrl, maximum: usize, items: usize, deadline: Instant) -> Self {
        Self {
            endpoint,
            seen: HashSet::new(),
            maximum,
            remaining_items: items,
            deadline,
        }
    }

    pub fn next(&mut self, candidate: &str) -> Result<PublicUrl> {
        if Instant::now() >= self.deadline {
            return Err(ErrorCode::Timeout);
        }
        if self.seen.len() >= self.maximum || self.remaining_items == 0 {
            return Err(ErrorCode::BudgetExceeded);
        }
        let target = PublicUrl::parse(candidate)?;
        if target.url().scheme() != "https"
            || target.origin() != self.endpoint.origin()
            || target.url().path() != self.endpoint.url().path()
            || target.url().fragment().is_some()
        {
            return Err(ErrorCode::PolicyDenied);
        }
        if !self.seen.insert(target.as_str().to_owned()) {
            return Err(ErrorCode::InvalidResponse);
        }
        Ok(target)
    }

    pub fn account_items(&mut self, count: usize) -> Result<()> {
        self.remaining_items = self
            .remaining_items
            .checked_sub(count)
            .ok_or(ErrorCode::SizeLimit)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rejects_private_and_disguised_destinations() {
        for target in [
            "file:///etc/shadow",
            "https://127.0.0.1",
            "http://2130706433",
            "http://0x7f000001",
            "https://[::1]",
            "https://[::ffff:127.0.0.1]",
            "https://169.254.169.254/latest",
            "https://100.100.100.100",
            "https://[fd7a:115c:a1e0::1]",
            "https://[64:ff9b::7f00:1]",
            "https://[2002:7f00:1::]",
            "https://localhost.",
            "https://host.ts.net",
            "https://user:secret@example.com",
            "https://@example.com",
            "https://example.com:8443",
            "https://example.com\\@127.0.0.1",
            " https://example.com",
        ] {
            assert!(PublicUrl::parse(target).is_err(), "{target}");
        }
    }

    #[test]
    fn validates_every_answer_not_only_the_first() {
        let public = "93.184.216.34:443".parse().unwrap();
        let private = "127.0.0.1:443".parse().unwrap();
        assert!(public_addresses(vec![public, private], &[]).is_err());
        assert!(public_addresses(vec![private, public], &[]).is_err());
        assert_eq!(
            public_addresses(vec![public, public], &[]).unwrap(),
            vec![public]
        );
        assert!(public_addresses(vec![], &[]).is_err());
        assert!(public_addresses(vec![public], &["93.184.216.0/24".parse().unwrap()]).is_err());
    }

    #[test]
    fn rejects_ipv6_transition_and_documentation_ranges() {
        for ip in [
            "::",
            "::ffff:8.8.8.8",
            "2001:db8::1",
            "3fff::1",
            "2002:0808:0808::1",
            "64:ff9b::808:808",
            "ff02::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap(), &[]), "{ip}");
        }
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap(), &[]));
    }

    #[test]
    fn signed_query_and_unicode_survive_normalization() {
        let target = PublicUrl::parse("https://example.com/a?sig=x%2Fy&b=2&b=1#part").unwrap();
        assert_eq!(
            target.request_url().as_str(),
            "https://example.com/a?sig=x%2Fy&b=2&b=1"
        );
        assert!(target.redirect("http://192.168.1.1/").is_err());
        assert_eq!(
            target.redirect("/next").unwrap().as_str(),
            "https://example.com/next"
        );
    }

    #[test]
    fn pagination_cannot_export_credentials_or_loop() {
        let endpoint = PublicUrl::parse("https://api.example.com/v2/crawl/job").unwrap();
        let mut guard =
            PaginationGuard::new(endpoint, 2, 10, Instant::now() + Duration::from_secs(1));
        assert_eq!(
            guard
                .next("https://attacker.example.com/v2/crawl/job")
                .unwrap_err(),
            ErrorCode::PolicyDenied
        );
        assert_eq!(
            guard
                .next("https://api.example.com/v2/crawl/foreign")
                .unwrap_err(),
            ErrorCode::PolicyDenied
        );
        guard
            .next("https://api.example.com/v2/crawl/job?skip=1")
            .unwrap();
        assert_eq!(
            guard
                .next("https://api.example.com/v2/crawl/job?skip=1")
                .unwrap_err(),
            ErrorCode::InvalidResponse
        );
        guard
            .next("https://api.example.com/v2/crawl/job?skip=2")
            .unwrap();
        assert_eq!(
            guard
                .next("https://api.example.com/v2/crawl/job?skip=3")
                .unwrap_err(),
            ErrorCode::BudgetExceeded
        );
        assert!(guard.account_items(11).is_err());
    }

    #[test]
    fn graphql_recipe_does_not_authorize_other_operations() {
        let query = "query Read { article { title } }";
        let rules = vec![ReadPostRule {
            origin: "https://example.com".into(),
            path: "/graphql".into(),
            max_bytes: 4096,
            operation: ReadPostOperation::Graphql {
                document_sha256: sha256(query.as_bytes()),
                operation_name: "Read".into(),
            },
        }];
        let target = PublicUrl::parse("https://example.com/graphql").unwrap();
        let accepted = serde_json::json!({"query":query,"operationName":"Read","variables":{}});
        assert!(read_post_allowed(
            &rules,
            &target,
            "application/json",
            &serde_json::to_vec(&accepted).unwrap()
        ));
        for body in [
            serde_json::json!({"query":"mutation Buy { purchase }","operationName":"Read"}),
            serde_json::json!({"query":query,"operationName":"Write"}),
            serde_json::json!({"query":query,"operationName":"Read","extensions":{"persistedQuery":{}}}),
            serde_json::json!([accepted]),
        ] {
            assert!(!read_post_allowed(
                &rules,
                &target,
                "application/json",
                &serde_json::to_vec(&body).unwrap()
            ));
        }
    }
}
