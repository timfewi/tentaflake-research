//! The five typed MCP operations. These schemas do not expose file paths,
//! headers, scripts, provider endpoints, network policy or arbitrary browser APIs.

#[cfg(feature = "service")]
use crate::archive::{Representation, Source};
use crate::error::{ErrorCode, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::config::{MAX_CRAWL_DEPTH, MAX_CRAWL_PAGES, MAX_FETCH_BATCH, MAX_SEARCH_BATCH};

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RequestedLimits {
    pub seconds: Option<u64>,
    pub bytes: Option<u64>,
    pub micro_usd: Option<u64>,
    pub queries: Option<u32>,
    pub documents: Option<u32>,
    pub requests: Option<u32>,
    pub pdf_pages: Option<u32>,
    pub browser_actions: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default = "default_count")]
    pub count: u8,
    pub language: Option<String>,
    pub country: Option<String>,
    pub freshness: Option<Freshness>,
}

fn default_count() -> u8 {
    10
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
pub enum Freshness {
    #[serde(rename = "pd")]
    Day,
    #[serde(rename = "pw")]
    Week,
    #[serde(rename = "pm")]
    Month,
    #[serde(rename = "py")]
    Year,
}

impl SearchQuery {
    pub fn validate(&self) -> Result<()> {
        if self.q.trim().is_empty()
            || self.q.chars().count() > 600
            || self.q.split_whitespace().count() > 75
            || self.q.contains('\0')
            || !(1..=20).contains(&self.count)
            || self.language.as_ref().is_some_and(|v| {
                !(2..=8).contains(&v.len())
                    || !v.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
            })
            || self
                .country
                .as_ref()
                .is_some_and(|v| v.len() != 2 || !v.bytes().all(|b| b.is_ascii_uppercase()))
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[schemars(transform = object_root)]
pub enum JobArgs {
    /// Inspect effective optional adapters without creating a job or using egress.
    Providers {},
    Start {
        #[serde(default)]
        limits: RequestedLimits,
    },
    Status {
        job_id: Uuid,
    },
    Finish {
        job_id: Uuid,
    },
    Cancel {
        job_id: Uuid,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    pub job_id: Uuid,
    #[schemars(length(min = 1, max = 128))]
    pub queries: Vec<SearchQuery>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FetchMode {
    /// Local HTTP fetch, with the existing browser hint only. Never routes to a
    /// scrape provider: escalation is always an explicit operator decision.
    #[default]
    Auto,
    Http,
    Browser,
    /// Explicit scrape-provider fetch. Still runs the selected-page robots
    /// policy check before any provider is called.
    Provider,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FetchArgs {
    pub job_id: Uuid,
    #[schemars(length(min = 1, max = 1000))]
    pub urls: Vec<String>,
    #[serde(default)]
    pub mode: FetchMode,
    /// Bounded same-origin crawl from each seed URL. Valid only with `http` or
    /// `auto`; it is not a general crawler and never crosses an origin boundary.
    #[serde(default)]
    pub crawl: Option<CrawlArgs>,
}

/// Explicit bounded crawl request. The service follows only same-origin links
/// discovered in the seed's extracted links representation, and the effective
/// page/depth bounds are the smaller of these values and the operator limits.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CrawlArgs {
    /// Total pages including the seed.
    #[schemars(range(min = 1, max = 64))]
    pub pages: u16,
    /// Maximum link hops from the seed; 0 fetches only the seed.
    #[schemars(range(min = 0, max = 5))]
    pub depth: u8,
}

impl CrawlArgs {
    /// The API schema bounds are enforced again here for in-process callers.
    pub fn validate(&self) -> Result<()> {
        if self.pages == 0 || self.pages > MAX_CRAWL_PAGES || self.depth > MAX_CRAWL_DEPTH {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScrollDirection {
    Down,
    Up,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[schemars(transform = object_root)]
pub enum BrowserArgs {
    Open {
        job_id: Uuid,
        url: String,
    },
    Read {
        job_id: Uuid,
        session_id: Uuid,
    },
    FollowLink {
        job_id: Uuid,
        session_id: Uuid,
        reference: String,
    },
    Expand {
        job_id: Uuid,
        session_id: Uuid,
        reference: String,
    },
    Scroll {
        job_id: Uuid,
        session_id: Uuid,
        direction: ScrollDirection,
    },
    Close {
        job_id: Uuid,
        session_id: Uuid,
    },
}

impl BrowserArgs {
    pub fn job_id(&self) -> Uuid {
        match self {
            Self::Open { job_id, .. }
            | Self::Read { job_id, .. }
            | Self::FollowLink { job_id, .. }
            | Self::Expand { job_id, .. }
            | Self::Scroll { job_id, .. }
            | Self::Close { job_id, .. } => *job_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[schemars(transform = object_root)]
pub enum ReadArgs {
    Metadata {
        source_id: Uuid,
    },
    Source {
        source_id: Uuid,
        representation_id: Uuid,
        cursor: Option<String>,
        start: Option<u64>,
        max_bytes: Option<usize>,
    },
    PdfPage {
        source_id: Uuid,
        page: u32,
        cursor: Option<String>,
        start: Option<u64>,
        max_bytes: Option<usize>,
    },
    Report {
        report_id: Uuid,
        #[serde(default)]
        start: u64,
        max_bytes: Option<usize>,
    },
    /// Optional, separately enabled expansion: send a saved text representation
    /// to a granted summarization provider and save the generated text as new
    /// evidence. It is paid job work (budget, cancellation, deadline), so a job
    /// is required; the saved source itself stays readable without any provider.
    Summary {
        job_id: Uuid,
        source_id: Uuid,
        /// Defaults to the source's primary text representation. Only text
        /// representations (`text: true`) can be summarized.
        representation_id: Option<Uuid>,
    },
}

// Tagged enum variants are objects. Preserve their oneOf validation while also
// declaring the root object type that MCP requires for every inputSchema.
fn object_root(schema: &mut schemars::Schema) {
    schema.insert("type".into(), serde_json::json!("object"));
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    Success,
    Empty,
    Partial,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub index: usize,
    pub state: ItemState,
    pub data: Option<serde_json::Value>,
    pub error: Option<ErrorCode>,
    pub duplicate_of: Option<usize>,
}

impl Item {
    pub fn failed(index: usize, error: ErrorCode) -> Self {
        Self {
            index,
            state: ItemState::Failed,
            data: None,
            error: Some(error),
            duplicate_of: None,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Coverage {
    pub success: usize,
    pub empty: usize,
    pub partial: usize,
    pub failed: usize,
    pub skipped: usize,
}
impl Coverage {
    pub fn from_items(items: &[Item]) -> Self {
        let mut coverage = Self::default();
        for item in items {
            match item.state {
                ItemState::Success => coverage.success += 1,
                ItemState::Empty => coverage.empty += 1,
                ItemState::Partial => coverage.partial += 1,
                ItemState::Failed => coverage.failed += 1,
                ItemState::Skipped => coverage.skipped += 1,
            }
        }
        coverage
    }
}

#[derive(Debug, Clone, Serialize)]
#[cfg(feature = "service")]
pub struct SourceBrief {
    pub id: Uuid,
    pub job_id: Uuid,
    pub original_url: String,
    pub final_url: String,
    pub provider: Option<String>,
    pub retrieved_at: i64,
    pub expires_at: i64,
    pub primary_representation: Option<Representation>,
    pub representations: usize,
    pub pdf_pages: usize,
    pub untrusted: bool,
    pub warnings: Vec<crate::archive::SourceWarning>,
}

#[cfg(feature = "service")]
impl From<&Source> for SourceBrief {
    fn from(source: &Source) -> Self {
        Self {
            id: source.id,
            job_id: source.job_id,
            original_url: source.original_url.clone(),
            final_url: source.final_url.clone(),
            provider: source.provider.clone(),
            retrieved_at: source.retrieved_at,
            expires_at: source.expires_at,
            primary_representation: source
                .representations
                .iter()
                .find(|r| {
                    matches!(
                        r.kind,
                        crate::archive::RepresentationKind::Text
                            | crate::archive::RepresentationKind::PdfPageText
                            | crate::archive::RepresentationKind::SearchResults
                    )
                })
                .or_else(|| source.representations.first())
                .cloned(),
            representations: source.representations.len(),
            pdf_pages: source
                .representations
                .iter()
                .filter(|r| r.pdf_page.is_some())
                .count(),
            untrusted: true,
            warnings: source.warnings.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_and_failed_coverage_cannot_be_reported_as_complete_empty() {
        let items = [
            Item {
                index: 0,
                state: ItemState::Empty,
                data: None,
                error: None,
                duplicate_of: None,
            },
            Item::failed(1, ErrorCode::Timeout),
        ];
        let coverage = Coverage::from_items(&items);
        assert_eq!(
            (coverage.empty, coverage.failed, coverage.success),
            (1, 1, 0)
        );
    }
    #[test]
    fn arbitrary_scripts_headers_and_provider_endpoints_are_not_tool_arguments() {
        assert!(serde_json::from_value::<BrowserArgs>(serde_json::json!({"action":"evaluate","job_id":Uuid::new_v4(),"script":"fetch('/delete')"})).is_err());
        assert!(serde_json::from_value::<FetchArgs>(serde_json::json!({"job_id":Uuid::new_v4(),"urls":[],"headers":{"Authorization":"secret"}})).is_err());
        assert!(serde_json::from_value::<SearchArgs>(serde_json::json!({"job_id":Uuid::new_v4(),"queries":[],"provider_url":"https://evil.test/"})).is_err());
        // A summary request selects saved evidence only: no prompt, model,
        // provider or endpoint can be supplied by the caller.
        for field in ["prompt", "model", "provider", "instructions", "endpoint"] {
            assert!(
                serde_json::from_value::<ReadArgs>(serde_json::json!({
                    "kind":"summary","job_id":Uuid::new_v4(),"source_id":Uuid::new_v4(),field:"x"
                }))
                .is_err(),
                "{field}"
            );
        }
        let summary: ReadArgs = serde_json::from_value(
            serde_json::json!({"kind":"summary","job_id":Uuid::new_v4(),"source_id":Uuid::new_v4()}),
        )
        .unwrap();
        assert!(matches!(
            summary,
            ReadArgs::Summary {
                representation_id: None,
                ..
            }
        ));
    }

    #[test]
    fn crawl_arguments_are_bounded_and_absent_means_a_normal_fetch() {
        // Absent `crawl` keeps exactly the previous fetch behavior.
        let plain: FetchArgs = serde_json::from_value(
            serde_json::json!({"job_id":Uuid::new_v4(),"urls":["https://example.com/"]}),
        )
        .unwrap();
        assert!(plain.crawl.is_none());
        assert!(
            CrawlArgs {
                pages: MAX_CRAWL_PAGES,
                depth: MAX_CRAWL_DEPTH
            }
            .validate()
            .is_ok()
        );
        for invalid in [
            CrawlArgs { pages: 0, depth: 0 },
            CrawlArgs {
                pages: MAX_CRAWL_PAGES + 1,
                depth: 0,
            },
            CrawlArgs {
                pages: 1,
                depth: MAX_CRAWL_DEPTH + 1,
            },
        ] {
            assert_eq!(invalid.validate(), Err(ErrorCode::InvalidRequest));
        }
        // A crawl object cannot smuggle unrelated fields or an arbitrary target.
        assert!(
            serde_json::from_value::<FetchArgs>(serde_json::json!({
                "job_id":Uuid::new_v4(),"urls":["https://example.com/"],
                "crawl":{"pages":1,"depth":0,"seed":"https://evil.test/"}
            }))
            .is_err()
        );
    }

    #[test]
    fn fetch_schema_exposes_a_bounded_optional_crawl_object() {
        let schema = serde_json::to_value(schemars::schema_for!(FetchArgs)).unwrap();
        let crawl = &schema["$defs"]["CrawlArgs"]["properties"];
        assert_eq!(crawl["pages"]["minimum"].as_u64(), Some(1));
        assert_eq!(
            crawl["pages"]["maximum"].as_u64(),
            Some(u64::from(MAX_CRAWL_PAGES))
        );
        assert_eq!(crawl["depth"]["minimum"].as_u64(), Some(0));
        assert_eq!(
            crawl["depth"]["maximum"].as_u64(),
            Some(u64::from(MAX_CRAWL_DEPTH))
        );
        assert!(
            !schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "crawl")
        );
    }
}
