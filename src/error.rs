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
