//! Fixed reading operations in an isolated JavaScript world. This module never
//! accepts a script, selector, arbitrary click or form input from its caller.
use super::{
    cdp::Cdp,
    wire::{Reference, ReferenceKind, Snapshot},
};
use crate::{
    api::ScrollDirection,
    error::{ErrorCode, Result},
    policy::{PublicUrl, sha256},
};
use chromiumoxide::cdp::{
    browser_protocol::{network, page},
    js_protocol::runtime,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

const SCRIPT: &str = include_str!("read.js");

pub struct PageSnapshot {
    pub metadata: Snapshot,
    pub html: Vec<u8>,
}

pub struct Reader {
    cdp: Arc<Cdp>,
    session: String,
    maximum_bytes: u64,
    context: Option<runtime::ExecutionContextId>,
    version: Option<Uuid>,
    document: Option<(page::FrameId, network::LoaderId)>,
    references: HashMap<String, ReferenceKind>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observed {
    url: String,
    title: String,
    html: String,
    references: Vec<Reference>,
    truncated: bool,
}

impl Reader {
    pub fn new(cdp: Arc<Cdp>, session: String, maximum_bytes: u64) -> Self {
        Self {
            cdp,
            session,
            maximum_bytes,
            context: None,
            version: None,
            document: None,
            references: HashMap::new(),
        }
    }

    pub fn invalidate(&mut self) {
        self.context = None;
        self.version = None;
        self.document = None;
        self.references.clear();
    }

    async fn evaluate(&self, arguments: Value) -> Result<Value> {
        let context = self.context.as_ref().ok_or(ErrorCode::StaleReference)?;
        if self.version.is_some() {
            let current = self
                .cdp
                .command::<page::GetFrameTreeParams>(Some(&self.session), json!({}))
                .await?
                .frame_tree
                .frame;
            if self.document.as_ref() != Some(&(current.id, current.loader_id)) {
                return Err(ErrorCode::StaleReference);
            }
        }
        let result = self
            .cdp
            .command::<runtime::EvaluateParams>(
                Some(&self.session),
                json!({
                    "expression":format!("({SCRIPT})({arguments})"),
                    "contextId":context, "returnByValue":true, "awaitPromise":false,
                }),
            )
            .await?;
        if result.exception_details.is_some() {
            return Err(ErrorCode::WorkerFailed);
        }
        let value = result.result.value.ok_or(ErrorCode::WorkerFailed)?;
        if let Some(error) = value.get("error") {
            return Err(match error.as_str() {
                Some("stale_reference") => ErrorCode::StaleReference,
                Some("size_limit") => ErrorCode::SizeLimit,
                _ => ErrorCode::PolicyDenied,
            });
        }
        Ok(value)
    }

    pub async fn read(&mut self) -> Result<PageSnapshot> {
        self.invalidate();
        let frame = self
            .cdp
            .command::<page::GetFrameTreeParams>(Some(&self.session), json!({}))
            .await?;
        let world = self.cdp.command::<page::CreateIsolatedWorldParams>(Some(&self.session), json!({
            "frameId":frame.frame_tree.frame.id, "worldName":"research-read-v1", "grantUniveralAccess":false,
        })).await?;
        self.document = Some((frame.frame_tree.frame.id, frame.frame_tree.frame.loader_id));
        self.context = Some(world.execution_context_id);
        let version = Uuid::new_v4();
        let observed: Observed = serde_json::from_value(
            self.evaluate(json!({
                "action":"snapshot", "version":version, "max_bytes":self.maximum_bytes,
            }))
            .await?,
        )
        .map_err(|_| ErrorCode::InvalidResponse)?;
        PublicUrl::parse(&observed.url)?;
        if observed.html.len() as u64 > self.maximum_bytes
            || observed.title.len() > 4096
            || observed.references.len() > 128
        {
            return Err(ErrorCode::SizeLimit);
        }
        let mut references = Vec::new();
        let mut truncated = observed.truncated;
        for (index, reference) in observed.references.into_iter().enumerate() {
            if reference.reference != format!("{version}:{index}") || reference.label.len() > 512 {
                return Err(ErrorCode::InvalidResponse);
            }
            if reference.kind == ReferenceKind::Link
                && reference
                    .url
                    .as_deref()
                    .is_none_or(|url| PublicUrl::parse(url).is_err())
            {
                truncated = true;
                continue;
            }
            self.references
                .insert(reference.reference.clone(), reference.kind);
            references.push(reference);
        }
        self.version = Some(version);
        let html = observed.html.into_bytes();
        Ok(PageSnapshot {
            metadata: Snapshot {
                version,
                url: observed.url,
                title: observed.title,
                html_bytes: html.len() as u64,
                html_sha256: sha256(&html),
                references,
                truncated_references: truncated,
                pending_requests: false,
                request_errors: vec![],
            },
            html,
        })
    }

    fn arguments(&self, reference: &str, kind: ReferenceKind, action: &str) -> Result<Value> {
        let version = self.version.ok_or(ErrorCode::StaleReference)?;
        if self.references.get(reference) != Some(&kind) {
            return Err(ErrorCode::StaleReference);
        }
        let (_, index) = reference.split_once(':').ok_or(ErrorCode::StaleReference)?;
        let index = index
            .parse::<usize>()
            .map_err(|_| ErrorCode::StaleReference)?;
        Ok(json!({"action":action, "version":version, "kind":kind, "index":index}))
    }

    /// Returns the observed URL for policy-checked navigation; never clicks a link.
    pub async fn follow_link(&self, reference: &str) -> Result<PublicUrl> {
        let value = self
            .evaluate(self.arguments(reference, ReferenceKind::Link, "follow_link")?)
            .await?;
        PublicUrl::parse(
            value
                .get("url")
                .and_then(Value::as_str)
                .ok_or(ErrorCode::InvalidResponse)?,
        )
    }

    pub async fn expand(&mut self, reference: &str) -> Result<()> {
        let arguments = self.arguments(reference, ReferenceKind::Expand, "expand")?;
        let result = self.evaluate(arguments).await;
        self.invalidate();
        result.map(|_| ())
    }

    pub async fn scroll(&mut self, direction: ScrollDirection) -> Result<()> {
        let version = self.version.ok_or(ErrorCode::StaleReference)?;
        let result = self.evaluate(json!({"action":"scroll", "version":version,
            "direction":match direction { ScrollDirection::Down => 1, ScrollDirection::Up => -1 },
        })).await;
        self.invalidate();
        result.map(|_| ())
    }
}
