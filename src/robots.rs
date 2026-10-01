//! Robots matching follows RFC 9309. Error handling includes the approved
//! selected-page exception; it never changes a successfully parsed disallow.

use crate::error::{ErrorCode, Result};
use crate::policy::PublicUrl;
use std::time::Duration;

const STAR: u16 = 1024;
const MATCH_STEPS: usize = 2_000_000;

#[derive(Debug, Clone)]
struct Rule {
    pattern: Vec<u16>,
    anchored: bool,
    specificity: usize,
    allow: bool,
}

#[derive(Debug, Clone, Default)]
struct Group {
    agents: Vec<String>,
    rules: Vec<Rule>,
    has_directive: bool,
    /// De-facto `Crawl-delay` (seconds) requested by this group; RFC 9309 does
    /// not define it but the expansion scope honors it for automatic crawling.
    crawl_delay: Option<u64>,
    /// De-facto `Request-rate: requests/seconds`, spaced evenly while crawling.
    request_interval: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct Rules {
    rules: Vec<Rule>,
    crawl_delay: Option<u64>,
    request_interval: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub enum AccessKind {
    SelectedPage,
    Discovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub warning: bool,
}

#[derive(Debug, Clone)]
pub enum RobotsDocument {
    Rules(Rules),
    Missing,
    Unavailable,
    Blocked,
    Throttled,
}

impl RobotsDocument {
    pub fn from_response(status: u16, body: &[u8], agent: &str, maximum: usize) -> Result<Self> {
        match status {
            200..=299 => Ok(Self::Rules(Rules::parse(body, agent, maximum)?)),
            404 | 410 => Ok(Self::Missing),
            401 | 403 | 407 | 451 => Ok(Self::Blocked),
            429 => Ok(Self::Throttled),
            400..=499 => Ok(Self::Missing),
            500..=599 => Ok(Self::Unavailable),
            // Redirect exhaustion and invalid responses are not network/5xx
            // exceptions. The caller must surface them as a failed policy check.
            _ => Err(ErrorCode::InvalidResponse),
        }
    }

    pub fn decide(
        &self,
        url: &PublicUrl,
        kind: AccessKind,
        selected_page_error_allows: bool,
    ) -> Result<Decision> {
        match self {
            Self::Rules(rules) if !rules.allowed(url)? => Err(ErrorCode::PolicyDenied),
            Self::Rules(_) | Self::Missing => Ok(Decision { warning: false }),
            Self::Unavailable
                if matches!(kind, AccessKind::SelectedPage) && selected_page_error_allows =>
            {
                Ok(Decision { warning: true })
            }
            Self::Unavailable => Err(ErrorCode::EgressUnavailable),
            Self::Blocked => Err(ErrorCode::AccessBlocked),
            Self::Throttled => Err(ErrorCode::RateLimited),
        }
    }
}

impl Rules {
    pub fn parse(bytes: &[u8], user_agent: &str, maximum: usize) -> Result<Self> {
        if bytes.len() > maximum || maximum > 4 * 1024 * 1024 {
            return Err(ErrorCode::SizeLimit);
        }
        let product = user_agent.split('/').next().unwrap_or("");
        if product.is_empty()
            || !product
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'-'))
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut groups = Vec::new();
        let mut group = Group::default();
        for line in bytes.split(|b| matches!(b, b'\n' | b'\r')) {
            // Invalid lines do not discard valid rules elsewhere in the file.
            let Ok(line) = std::str::from_utf8(line) else {
                continue;
            };
            let line = line
                .trim_start_matches('\u{feff}')
                .split('#')
                .next()
                .unwrap_or("")
                .trim();
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "user-agent" => {
                    if group.has_directive {
                        groups.push(group);
                        group = Group::default();
                    }
                    if value == "*"
                        || (!value.is_empty()
                            && value
                                .bytes()
                                .all(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'-')))
                    {
                        group.agents.push(value.to_ascii_lowercase());
                    }
                }
                name @ ("allow" | "disallow") if !group.agents.is_empty() => {
                    group.has_directive = true;
                    if !value.starts_with('/') || value.bytes().any(|b| b <= 0x20 || b == 0x7f) {
                        continue;
                    }
                    let anchored = value.ends_with('$');
                    let value = if anchored {
                        &value[..value.len() - 1]
                    } else {
                        value
                    };
                    let pattern = octets(value, true);
                    let specificity = pattern.iter().filter(|v| **v != STAR).count();
                    group.rules.push(Rule {
                        pattern,
                        anchored,
                        specificity,
                        allow: name == "allow",
                    });
                }
                "crawl-delay" if !group.agents.is_empty() => {
                    group.has_directive = true;
                    // Bounded, and only a single whole-second value is accepted;
                    // malformed values are ignored and excessive delays are capped.
                    if let Ok(seconds) = value.parse::<u64>() {
                        group.crawl_delay = Some(seconds.min(3600));
                    }
                }
                "request-rate" if !group.agents.is_empty() => {
                    group.has_directive = true;
                    if let Some((requests, seconds)) = value.split_once('/')
                        && let (Ok(requests), Ok(seconds)) = (
                            requests.trim().parse::<u64>(),
                            seconds.trim().parse::<u64>(),
                        )
                        && requests > 0
                        && seconds > 0
                    {
                        // Round up so the interval never permits more than
                        // the requested rate, then cap the resulting pause.
                        let nanos = u128::from(seconds) * 1_000_000_000;
                        let interval = nanos
                            .div_ceil(u128::from(requests))
                            .clamp(1, 3_600_000_000_000)
                            as u64;
                        let interval = Duration::from_nanos(interval);
                        group.request_interval =
                            Some(group.request_interval.unwrap_or_default().max(interval));
                    }
                }
                _ => (), // Sitemap and unknown extensions do not delimit groups.
            }
        }
        groups.push(group);
        let explicit = groups
            .iter()
            .any(|g| g.agents.iter().any(|a| a.eq_ignore_ascii_case(product)));
        let matches = |g: &Group| {
            g.agents.iter().any(|a| {
                if explicit {
                    a.eq_ignore_ascii_case(product)
                } else {
                    a == "*"
                }
            })
        };
        // The requested delay for the selected agent group (largest wins).
        let crawl_delay = groups
            .iter()
            .filter(|g| matches(g))
            .filter_map(|g| g.crawl_delay)
            .max();
        let request_interval = groups
            .iter()
            .filter(|g| matches(g))
            .filter_map(|g| g.request_interval)
            .max();
        let rules = groups
            .into_iter()
            .filter(matches)
            .flat_map(|g| g.rules)
            .collect();
        Ok(Self {
            rules,
            crawl_delay,
            request_interval,
        })
    }

    /// Seconds between automatic crawl requests requested by the matched group.
    pub fn crawl_delay(&self) -> Option<u64> {
        self.crawl_delay
    }

    /// Minimum spacing between automatic requests in this crawl. The stricter
    /// of the matched groups' Crawl-delay and Request-rate directives wins.
    pub fn crawl_interval(&self) -> Duration {
        Duration::from_secs(self.crawl_delay.unwrap_or(0))
            .max(self.request_interval.unwrap_or_default())
    }

    pub fn allowed(&self, url: &PublicUrl) -> Result<bool> {
        if url.url().path() == "/robots.txt" {
            return Ok(true);
        }
        let path = &url.request_url()[url::Position::BeforePath..];
        let path = octets(path, false);
        let mut steps = MATCH_STEPS;
        let mut matched: Option<(usize, bool)> = None;
        for rule in &self.rules {
            if matched.is_some_and(|(specificity, allow)| {
                specificity > rule.specificity || (specificity == rule.specificity && allow)
            }) {
                continue;
            }
            if glob(&rule.pattern, &path, rule.anchored, &mut steps)? {
                matched = Some((rule.specificity, rule.allow));
            }
        }
        Ok(matched.is_none_or(|(_, allow)| allow))
    }
}

fn octets(value: &str, pattern: bool) -> Vec<u16> {
    let mut output = Vec::with_capacity(value.len());
    let mut bytes = value.bytes().peekable();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let mut rest = bytes.clone();
            let decoded = rest
                .next()
                .and_then(hex)
                .and_then(|a| rest.next().and_then(hex).map(|b| a * 16 + b));
            if let Some(decoded) = decoded {
                bytes = rest;
                output.push(if unreserved(decoded) {
                    decoded as u16
                } else {
                    256 + decoded as u16
                });
                continue;
            }
        }
        output.push(match byte {
            b'*' if pattern => STAR,
            b'*' | b'$' | 128..=255 => 256 + byte as u16,
            _ => byte as u16,
        });
    }
    output
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn glob(pattern: &[u16], value: &[u16], anchored: bool, steps: &mut usize) -> Result<bool> {
    let (mut p, mut v) = (0, 0);
    let mut star = None;
    loop {
        *steps = steps.checked_sub(1).ok_or(ErrorCode::PolicyDenied)?;
        if p == pattern.len() && (!anchored || v == value.len()) {
            return Ok(true);
        }
        if pattern.get(p) == Some(&STAR) {
            p += 1;
            star = Some((p, v));
        } else if v < value.len() && pattern.get(p) == value.get(v) {
            p += 1;
            v += 1;
        } else if let Some((after, start)) = star {
            if start == value.len() {
                return Ok(false);
            }
            star = Some((after, start + 1));
            p = after;
            v = start + 1;
        } else {
            return Ok(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> Rules {
        Rules::parse(text.as_bytes(), "PublicResearch/0.1", 512 * 1024).unwrap()
    }
    fn url(path: &str) -> PublicUrl {
        PublicUrl::parse(&format!("https://example.com{path}")).unwrap()
    }

    #[test]
    fn explicit_groups_merge_and_do_not_inherit_wildcard() {
        let rules = rules(
            "User-agent: *\nDisallow: /\n\nUser-agent: PublicResearch\nDisallow: /one\n\nUser-agent: publicresearch\nDisallow: /two\nAllow: /one/public",
        );
        assert!(rules.allowed(&url("/free")).unwrap());
        assert!(!rules.allowed(&url("/one")).unwrap());
        assert!(!rules.allowed(&url("/two")).unwrap());
        assert!(rules.allowed(&url("/one/public")).unwrap());
        assert!(rules.allowed(&url("/robots.txt")).unwrap());
    }

    #[test]
    fn wildcard_and_end_anchor_use_case_sensitive_longest_rule() {
        let rules = rules(
            "User-agent: *\nDisallow: /*.pdf$\nDisallow: /private\nAllow: /private\nDisallow: /private/secret\n",
        );
        assert!(!rules.allowed(&url("/document.pdf")).unwrap());
        assert!(rules.allowed(&url("/document.pdf?download=1")).unwrap());
        assert!(rules.allowed(&url("/private")).unwrap());
        assert!(!rules.allowed(&url("/private/secret")).unwrap());
        assert!(rules.allowed(&url("/PRIVATE/secret")).unwrap());
    }

    #[test]
    fn encoded_unicode_and_unreserved_characters_match_without_decoding_slashes() {
        let rules = rules(
            "User-agent: *\nDisallow: /café\nDisallow: /%7euser\nDisallow: /a%2Fb\nDisallow: /literal%2A\n",
        );
        for path in [
            "/caf%C3%A9",
            "/café",
            "/~user",
            "/%7Euser",
            "/a%2fb",
            "/literal*",
        ] {
            assert!(!rules.allowed(&url(path)).unwrap(), "{path}");
        }
        assert!(rules.allowed(&url("/a/b")).unwrap());
        assert!(rules.allowed(&url("/literal-more")).unwrap());
    }

    #[test]
    fn empty_disallow_unknown_records_and_multiple_agents_parse() {
        let rules = rules(
            "User-agent: OtherBot\nUser-agent: PublicResearch\nSitemap: https://example.com/map\nDisallow:\nAllow: /\nDisallow: /blocked # comment\n",
        );
        assert!(rules.allowed(&url("/ok")).unwrap());
        assert!(!rules.allowed(&url("/blocked")).unwrap());
        assert!(Rules::parse(b"", "bad-agent/1", 512 * 1024).is_ok());
    }

    #[test]
    fn network_exception_never_overrides_disallow_or_access_block() {
        let unavailable = RobotsDocument::Unavailable;
        assert!(
            unavailable
                .decide(&url("/"), AccessKind::SelectedPage, true)
                .unwrap()
                .warning
        );
        assert!(
            unavailable
                .decide(&url("/"), AccessKind::Discovery, true)
                .is_err()
        );
        assert!(
            unavailable
                .decide(&url("/"), AccessKind::SelectedPage, false)
                .is_err()
        );
        let denied = RobotsDocument::Rules(rules("User-agent: *\nDisallow: /"));
        assert_eq!(
            denied.decide(&url("/page"), AccessKind::SelectedPage, true),
            Err(ErrorCode::PolicyDenied)
        );
        for status in [401, 403, 407, 429, 451] {
            let document =
                RobotsDocument::from_response(status, b"", "PublicResearch/0.1", 512 * 1024)
                    .unwrap();
            assert!(
                document
                    .decide(&url("/"), AccessKind::SelectedPage, true)
                    .is_err()
            );
        }
    }

    #[test]
    fn crawl_delay_is_parsed_per_group_and_bounded() {
        let parsed = rules(
            "User-agent: *\nCrawl-delay: 2.5\nDisallow: /x\nUser-agent: PublicResearch\nCrawl-delay: 7\nDisallow: /y\n",
        );
        // The explicit agent's group wins; the wildcard group is not inherited.
        assert_eq!(parsed.crawl_delay(), Some(7));
        let wildcard = rules("User-agent: *\nCrawl-delay: 3\nDisallow: /x\n");
        assert_eq!(wildcard.crawl_delay(), Some(3));
        // Excessive values are capped; malformed values are ignored.
        let excessive = rules("User-agent: *\nCrawl-delay: 99999\nDisallow: /x\n");
        assert_eq!(excessive.crawl_delay(), Some(3600));
        let malformed = rules("User-agent: *\nCrawl-delay: abc\nDisallow: /x\n");
        assert_eq!(malformed.crawl_delay(), None);
    }

    #[test]
    fn crawl_delay_ends_a_group_before_the_next_agent() {
        let parsed = rules(
            "User-agent: PublicResearch\nCrawl-delay: 7\nUser-agent: OtherBot\nDisallow: /private\n",
        );
        assert_eq!(parsed.crawl_delay(), Some(7));
        assert!(parsed.allowed(&url("/private")).unwrap());
        let malformed = rules(
            "User-agent: PublicResearch\nCrawl-delay: invalid\nUser-agent: OtherBot\nDisallow: /private\n",
        );
        assert_eq!(malformed.crawl_delay(), None);
        assert!(malformed.allowed(&url("/private")).unwrap());
        let wildcard = rules(
            "User-agent: *\nCrawl-delay: 3\nUser-agent: PublicResearch\nDisallow: /private\n",
        );
        assert_eq!(wildcard.crawl_delay(), None);
        assert!(!wildcard.allowed(&url("/private")).unwrap());
    }

    #[test]
    fn request_rate_uses_the_selected_group_and_bounds_the_interval() {
        let parsed = rules(
            "User-agent: *\nRequest-rate: 1/10\nUser-agent: PublicResearch\nRequest-rate: 3/2\nUser-agent: publicresearch\nCrawl-delay: 1\n",
        );
        assert_eq!(parsed.crawl_interval(), std::time::Duration::from_secs(1));
        let wildcard = rules("User-agent: *\nRequest-rate: 3 / 2\n");
        assert_eq!(
            wildcard.crawl_interval(),
            std::time::Duration::from_nanos(666_666_667)
        );
        let bounded = rules("User-agent: *\nRequest-rate: 1/99999\n");
        assert_eq!(
            bounded.crawl_interval(),
            std::time::Duration::from_secs(3600)
        );
        let bounded = rules("User-agent: *\nRequest-rate: 2/99999\n");
        assert_eq!(
            bounded.crawl_interval(),
            std::time::Duration::from_secs(3600)
        );
    }

    #[test]
    fn invalid_request_rate_still_ends_its_group() {
        for value in ["0/10", "1/0", "invalid", "1/2/3"] {
            let parsed = rules(&format!(
                "User-agent: PublicResearch\nRequest-rate: {value}\nUser-agent: OtherBot\nDisallow: /private\n"
            ));
            assert_eq!(parsed.crawl_interval(), std::time::Duration::ZERO);
            assert!(parsed.allowed(&url("/private")).unwrap());
        }
    }

    #[test]
    fn complex_matches_have_a_fixed_cpu_budget() {
        let mut steps = 10;
        assert_eq!(
            glob(
                &octets("/*aaaaaab", true),
                &octets(&format!("/{}", "a".repeat(100)), false),
                false,
                &mut steps
            ),
            Err(ErrorCode::PolicyDenied)
        );
    }
}
