use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Machine-readable failures contain service-authored text only. Never serialize
/// an upstream exception, request, response body, or credential into diagnostics.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error,
)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    #[error("invalid request")]
    InvalidRequest,
    #[error("unsupported protocol version")]
    ProtocolVersion,
    #[error("permission denied")]
    PermissionDenied,
    #[error("destination is not public")]
    DestinationDenied,
    #[error("policy does not allow this operation")]
    PolicyDenied,
    #[error("browser identity does not match the pinned Chromium identity")]
    BrowserIdentityMismatch,
    #[error("browser request is outside the reviewed method/header/operation grant")]
    BrowserRequestDenied,
    #[error("robots policy denies the browser destination")]
    BrowserRobotsDenied,
    #[error("provider is not configured for this capability")]
    ProviderUnavailable,
    #[error("provider authentication failed")]
    Authentication,
    #[error("provider returned invalid data")]
    InvalidResponse,
    #[error("rate limit reached")]
    RateLimited,
    #[error("access restriction encountered")]
    AccessBlocked,
    #[error("protected egress unavailable")]
    EgressUnavailable,
    #[error("egress changed during the operation")]
    EgressChanged,
    #[error("budget exhausted")]
    BudgetExceeded,
    #[error("size limit reached")]
    SizeLimit,
    #[error("operation timed out")]
    Timeout,
    #[error("operation cancelled")]
    Cancelled,
    #[error("job is not active")]
    JobClosed,
    #[error("resource not found")]
    NotFound,
    #[error("resource expired or was evicted")]
    SourceExpired,
    #[error("page reference is stale")]
    StaleReference,
    #[error("resource requires OCR")]
    OcrRequired,
    #[error("document is encrypted")]
    EncryptedDocument,
    #[error("extraction failed")]
    ExtractionFailed,
    #[error("worker failed")]
    WorkerFailed,
    #[error("storage operation failed")]
    Storage,
    #[error("service is at capacity")]
    Capacity,
}

pub type Result<T> = std::result::Result<T, ErrorCode>;

/// Diagnostic values are fixed enums and validated numeric limits, never
/// upstream text, headers, URLs, credentials or filesystem paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolFailure {
    #[serde(rename = "error")]
    pub code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub details: Option<ErrorDetails>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErrorDetails {
    JobLimits { violations: Vec<LimitViolation> },
    BrowserIdentityMismatch,
    BrowserRequestNotGranted,
    RobotsDisallowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitField {
    Seconds,
    Bytes,
    MicroUsd,
    Queries,
    Documents,
    Requests,
    PdfPages,
    BrowserActions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitViolation {
    pub field: LimitField,
    pub requested: u64,
    pub minimum: u64,
    pub maximum: u64,
}

impl From<ErrorCode> for ToolFailure {
    fn from(code: ErrorCode) -> Self {
        let details = match code {
            ErrorCode::BrowserIdentityMismatch => Some(ErrorDetails::BrowserIdentityMismatch),
            ErrorCode::BrowserRequestDenied => Some(ErrorDetails::BrowserRequestNotGranted),
            ErrorCode::BrowserRobotsDenied => Some(ErrorDetails::RobotsDisallowed),
            _ => None,
        };
        Self {
            code: if details.is_some() {
                ErrorCode::PolicyDenied
            } else {
                code
            },
            details,
        }
    }
}
