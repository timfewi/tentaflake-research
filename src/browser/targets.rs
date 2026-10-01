//! Target ownership and setup before execution. The event consumer must call
//! handle before processing network events and close the browser on any error.
use super::{
    cdp::{Cdp, Event},
    launch::Settings,
};
use crate::error::{ErrorCode, Result};
use chromiumoxide::cdp::{
    browser_protocol::{browser, emulation, fetch, network, page, target},
    js_protocol::runtime,
};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;

const MAX_TARGETS: usize = 64;

pub struct Targets {
    cdp: Arc<Cdp>,
    settings: Settings,
    main_target: String,
    main_session: Option<String>,
    sessions: HashMap<String, String>,
    paused: HashSet<String>,
    attachments: usize,
    pub blocked_targets: usize,
}

impl Targets {
    /// No public navigation occurs until this returns. Existing about:blank is
    /// harmless while browser-wide auto-attachment takes ownership of it.
    pub async fn create(
        cdp: Arc<Cdp>,
        settings: &Settings,
        events: &mut mpsc::Receiver<Event>,
    ) -> Result<Self> {
        settings.validate()?;
        cdp.command::<browser::SetDownloadBehaviorParams>(None, json!({"behavior":"deny"}))
            .await?;
        let created = cdp
            .command::<target::CreateTargetParams>(None, json!({"url":"about:blank"}))
            .await?;
        let mut this = Self {
            cdp,
            settings: settings.clone(),
            main_target: created.target_id.as_ref().to_owned(),
            main_session: None,
            sessions: HashMap::new(),
            paused: HashSet::new(),
            attachments: 0,
            blocked_targets: 0,
        };
        this.auto_attach(None).await?;
        tokio::time::timeout(Duration::from_secs(settings.operation_seconds), async {
            while this.main_session.is_none() {
                let event = events.recv().await.ok_or(ErrorCode::WorkerFailed)?;
                if !this.handle(&event).await? && event.method.starts_with("Fetch.") {
                    return Err(ErrorCode::WorkerFailed);
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| ErrorCode::Timeout)??;
        Ok(this)
    }

    pub fn main_session(&self) -> &str {
        self.main_session
            .as_deref()
            .expect("main target initialized")
    }

    pub fn owns_session(&self, session: Option<&str>) -> bool {
        session.is_some_and(|session| self.sessions.contains_key(session))
    }

    async fn auto_attach(&self, session: Option<&str>) -> Result<()> {
        self.cdp
            .command::<target::SetAutoAttachParams>(
                session,
                json!({
                    "autoAttach":true, "waitForDebuggerOnStart":true, "flatten":true,
                    "filter":[{"type":"browser","exclude":true},{"type":"browser_ui","exclude":true},{"type":"tab","exclude":true},{}],
                }),
            )
            .await?;
        Ok(())
    }

    async fn configure(&self, session: &str, main: bool) -> Result<()> {
        let at = Some(session);
        self.cdp
            .command::<page::EnableParams>(at, json!({}))
            .await?;
        self.cdp
            .command::<network::EnableParams>(at, json!({"maxPostDataSize":65536}))
            .await?;
        self.cdp
            .command::<network::SetCacheDisabledParams>(at, json!({"cacheDisabled":true}))
            .await?;
        self.cdp
            .command::<network::SetBypassServiceWorkerParams>(at, json!({"bypass":true}))
            .await?;
        self.cdp
            .command::<network::SetBlockedUrLsParams>(
                at,
                json!({"urls":["ws://*","wss://*","file://*","ftp://*"]}),
            )
            .await?;
        self.cdp.command::<fetch::EnableParams>(at, json!({
            "patterns":[{"urlPattern":"*","requestStage":"Request"}], "handleAuthRequests":true,
        })).await?;
        self.cdp
            .command::<page::SetLifecycleEventsEnabledParams>(at, json!({"enabled":true}))
            .await?;
        self.cdp
            .command::<emulation::SetLocaleOverrideParams>(
                at,
                json!({"locale": self.settings.locale}),
            )
            .await?;
        self.cdp
            .command::<emulation::SetTimezoneOverrideParams>(
                at,
                json!({"timezoneId": self.settings.timezone}),
            )
            .await?;
        if main {
            self.cdp
                .command::<emulation::SetDeviceMetricsOverrideParams>(
                    at,
                    json!({
                        "width":self.settings.width, "height":self.settings.height,
                        "screenWidth":self.settings.width, "screenHeight":self.settings.height,
                        "deviceScaleFactor":1, "mobile":false,
                    }),
                )
                .await?;
        }
        self.auto_attach(at).await?;
        Ok(())
    }

    /// Returns true for consumed control events. Unknown sessions must not be
    /// granted network access by the caller, even if they emit Fetch events.
    pub async fn handle(&mut self, event: &Event) -> Result<bool> {
        match event.method.as_str() {
            "Target.attachedToTarget" => {
                let attached: target::EventAttachedToTarget =
                    serde_json::from_value(event.params.clone())
                        .map_err(|_| ErrorCode::WorkerFailed)?;
                self.attachments += 1;
                if self.attachments > MAX_TARGETS || self.sessions.len() >= MAX_TARGETS {
                    return Err(ErrorCode::Capacity);
                }
                let session = attached.session_id.as_ref();
                let id = attached.target_info.target_id.as_ref();
                let main = id == self.main_target;
                let frame = attached.target_info.r#type == "iframe"
                    && self.owns_session(event.session.as_deref());
                if (!main && !frame) || attached.target_info.subtype.is_some() {
                    self.blocked_targets += 1;
                    if attached.target_info.r#type == "page" {
                        // Closing a debugger-paused popup can deadlock the
                        // opener's synchronous window.open. Disable execution
                        // and all URL requests before releasing that pause,
                        // then close it. This session never gets broker access.
                        self.cdp
                            .command::<emulation::SetScriptExecutionDisabledParams>(
                                Some(session),
                                json!({"value":true}),
                            )
                            .await?;
                        self.cdp
                            .command::<network::EnableParams>(Some(session), json!({}))
                            .await?;
                        self.cdp
                            .command::<network::SetBlockedUrLsParams>(
                                Some(session),
                                json!({"urls":["*"]}),
                            )
                            .await?;
                        self.cdp
                            .command::<runtime::RunIfWaitingForDebuggerParams>(
                                Some(session),
                                json!({}),
                            )
                            .await?;
                        self.cdp
                            .command::<target::CloseTargetParams>(None, json!({"targetId":id}))
                            .await?;
                    } else {
                        // Chromium rejects CloseTarget for dedicated workers.
                        // Keep unsupported targets paused, attached and without
                        // network authority until the supervisor destroys the
                        // browser. Never detach: that would resume execution.
                        if !attached.waiting_for_debugger {
                            return Err(ErrorCode::PolicyDenied);
                        }
                        self.paused.insert(session.to_owned());
                    }
                    return Ok(true);
                }
                // A second session for the same target would otherwise install
                // competing interception handlers and obscure ownership.
                if self.sessions.values().any(|known| known == id)
                    || (!main && !attached.waiting_for_debugger)
                {
                    return Err(ErrorCode::WorkerFailed);
                }
                self.configure(session, main).await?;
                self.sessions.insert(session.to_owned(), id.to_owned());
                if main {
                    self.main_session = Some(session.to_owned());
                }
                self.cdp
                    .command::<runtime::RunIfWaitingForDebuggerParams>(Some(session), json!({}))
                    .await?;
                Ok(true)
            }
            "Target.detachedFromTarget" => {
                let session = event
                    .params
                    .get("sessionId")
                    .and_then(|v| v.as_str())
                    .ok_or(ErrorCode::WorkerFailed)?;
                self.sessions.remove(session);
                self.paused.remove(session);
                if self.main_session.as_deref() == Some(session) {
                    return Err(ErrorCode::WorkerFailed);
                }
                Ok(true)
            }
            "Fetch.authRequired" => {
                if !self.owns_session(event.session.as_deref()) {
                    return Err(ErrorCode::PolicyDenied);
                }
                let id = event
                    .params
                    .get("requestId")
                    .and_then(|v| v.as_str())
                    .ok_or(ErrorCode::WorkerFailed)?;
                self.cdp
                    .command::<fetch::ContinueWithAuthParams>(
                        event.session.as_deref(),
                        json!({
                            "requestId":id,"authChallengeResponse":{"response":"CancelAuth"},
                        }),
                    )
                    .await?;
                Ok(true)
            }
            "Inspector.targetCrashed" => Err(ErrorCode::WorkerFailed),
            _ => Ok(false),
        }
    }
}
