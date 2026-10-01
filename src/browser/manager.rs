//! Production job/owner lookup and evidence publication. Session IDs are opaque
//! handles within the same operator trust domain, never independent credentials.
use super::{
    broker::JobBroker,
    engine::WorkerSettings,
    launch::Settings,
    profile::Profile,
    sandbox::SandboxConfig,
    session::{Pool, Session},
    wire,
};
use crate::{
    api::{BrowserArgs, SourceBrief},
    budget::{Charge, Ledger},
    config::Config,
    error::{ErrorCode, Result},
    fetch::Fetcher,
    policy::PublicUrl,
    provider::Context,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

pub(crate) fn settings(config: &Config) -> WorkerSettings {
    let profile = Profile::neutral();
    WorkerSettings {
        launch: Settings {
            chromium: config.browser.executable.clone(),
            width: config.browser.width,
            height: config.browser.height,
            operation_seconds: config.limits.browser_seconds,
            html_bytes: config.limits.html_bytes,
            requests: config.limits.requests,
            actions: config.limits.browser_actions,
            locale: profile.locale,
            timezone: profile.timezone,
            accept_language: profile.accept_language,
        },
        read_post_rules: config.browser.read_post_rules.clone(),
        redirects: config.limits.redirects as u32,
        response_bytes: config.limits.pdf_bytes,
        idle_seconds: config.browser.idle_seconds,
        // Sessions are always shorter lived than their owning job. A longer
        // operator job can open a fresh session after the worker lifetime cap.
        lifetime_seconds: config.limits.job_seconds.min(600),
    }
}

/// Capture one session's fixed profile. A running session's settings are never
/// rewritten, so a later exit-region change cannot alter it mid-session; only a
/// newly created session picks up the new region.
fn session_settings(base: &WorkerSettings, profile: &Profile) -> WorkerSettings {
    let mut settings = base.clone();
    settings.launch.locale = profile.locale.clone();
    settings.launch.timezone = profile.timezone.clone();
    settings.launch.accept_language = profile.accept_language.clone();
    settings
}

struct Entry {
    owner: u32,
    job: Uuid,
    original: Mutex<PublicUrl>,
    page: Mutex<Option<wire::Snapshot>>,
    session: Session,
    broker: Arc<JobBroker>,
    action: tokio::sync::Mutex<()>,
}

pub struct Manager {
    pool: Pool,
    sandbox: SandboxConfig,
    settings: WorkerSettings,
    temporary: PathBuf,
    fetcher: Arc<Fetcher>,
    ledger: Arc<Ledger>,
    sessions: Mutex<HashMap<Uuid, Arc<Entry>>>,
}

impl Manager {
    pub fn new(
        config: &Config,
        temporary: PathBuf,
        fetcher: Arc<Fetcher>,
        ledger: Arc<Ledger>,
    ) -> Result<Self> {
        let settings = settings(config);
        settings.validate()?;
        let sandbox = config
            .browser
            .sandbox
            .clone()
            .ok_or(ErrorCode::InvalidRequest)?;
        sandbox.validate()?;
        if !temporary.is_absolute() {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            pool: Pool::new(config.limits.browser_concurrency)?,
            sandbox,
            settings,
            temporary,
            fetcher,
            ledger,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn entry(&self, context: &Context, id: Uuid) -> Result<Arc<Entry>> {
        self.sessions
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .get(&id)
            .filter(|entry| entry.owner == context.owner && entry.job == context.job)
            .cloned()
            .ok_or(ErrorCode::NotFound)
    }

    fn remove(&self, id: Uuid) -> Result<()> {
        self.sessions
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .remove(&id);
        Ok(())
    }

    pub async fn finish_job(&self, owner: u32, job: Uuid) -> Result<()> {
        let entries = {
            let sessions = self.sessions.lock().map_err(|_| ErrorCode::Storage)?;
            sessions
                .iter()
                .filter(|(_, entry)| entry.owner == owner && entry.job == job)
                .map(|(id, entry)| (*id, entry.clone()))
                .collect::<Vec<_>>()
        };
        for (id, entry) in entries {
            entry.session.close().await;
            self.remove(id)?;
        }
        Ok(())
    }

    pub async fn maintenance(&self) -> Result<()> {
        let entries = {
            let sessions = self.sessions.lock().map_err(|_| ErrorCode::Storage)?;
            sessions
                .iter()
                .filter(|(_, entry)| entry.session.is_closed())
                .map(|(id, entry)| (*id, entry.clone()))
                .collect::<Vec<_>>()
        };
        // Cancellation starts cleanup; only close() proves it has completed.
        // Keep draining entries discoverable so concurrent job shutdown waits
        // for their archive writes before deleting strict evidence.
        for (id, entry) in entries {
            entry.session.close().await;
            self.remove(id)?;
        }
        Ok(())
    }

    pub async fn execute(
        &self,
        context: &Context,
        args: BrowserArgs,
        profile: &Profile,
    ) -> Result<Value> {
        profile.validate()?;
        if args.job_id() != context.job {
            return Err(ErrorCode::PermissionDenied);
        }
        if context.stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        let (id, entry, action, opening) = match args {
            BrowserArgs::Open { url, .. } => {
                let original = PublicUrl::parse(&url)?;
                self.charge(context)?;
                self.maintenance().await?;
                // Normal completion does not cancel the opening call token.
                // Cancellation while returning its ID must still end the worker.
                let session_stop = context.stop.child_token();
                let guard = session_stop.clone().drop_guard();
                let broker = Arc::new(JobBroker::new(
                    self.fetcher.clone(),
                    Context {
                        owner: context.owner,
                        job: context.job,
                        deadline: context.deadline,
                        stop: session_stop.clone(),
                    },
                    self.settings.launch.requests,
                )?);
                let starting = self.pool.start(
                    &self.sandbox,
                    session_settings(&self.settings, profile),
                    &self.temporary,
                    broker.clone(),
                    &session_stop,
                );
                tokio::pin!(starting);
                let session = tokio::select! {
                    biased;
                    _ = context.stop.cancelled() => {
                        session_stop.cancel();
                        if let Ok(session) = starting.await { session.close().await; }
                        return Err(ErrorCode::Cancelled);
                    },
                    result = &mut starting => result?,
                };
                guard.disarm();
                let entry = Arc::new(Entry {
                    owner: context.owner,
                    job: context.job,
                    original: Mutex::new(original),
                    page: Mutex::new(None),
                    session,
                    broker,
                    action: tokio::sync::Mutex::new(()),
                });
                let id = Uuid::new_v4();
                self.sessions
                    .lock()
                    .map_err(|_| ErrorCode::Storage)?
                    .insert(id, entry.clone());
                (id, entry, wire::Action::Open { url }, true)
            }
            action => {
                let (id, action) = match action {
                    BrowserArgs::Read { session_id, .. } => (session_id, wire::Action::Read),
                    BrowserArgs::FollowLink {
                        session_id,
                        reference,
                        ..
                    } => (session_id, wire::Action::FollowLink { reference }),
                    BrowserArgs::Expand {
                        session_id,
                        reference,
                        ..
                    } => (session_id, wire::Action::Expand { reference }),
                    BrowserArgs::Scroll {
                        session_id,
                        direction,
                        ..
                    } => (session_id, wire::Action::Scroll { direction }),
                    BrowserArgs::Close { session_id, .. } => (session_id, wire::Action::Close),
                    BrowserArgs::Open { .. } => return Err(ErrorCode::InvalidRequest),
                };
                (id, self.entry(context, id)?, action, false)
            }
        };
        let _action = entry.action.try_lock().map_err(|_| ErrorCode::Capacity)?;
        let destination = match &action {
            wire::Action::FollowLink { reference } => entry
                .page
                .lock()
                .map_err(|_| ErrorCode::Storage)?
                .as_ref()
                .and_then(|page| {
                    page.references
                        .iter()
                        .find(|item| item.reference == *reference)
                })
                .and_then(|item| item.url.as_ref())
                .map(|url| PublicUrl::parse(url))
                .transpose()?,
            _ => None,
        };
        let close = matches!(action, wire::Action::Close);
        if !opening && !close {
            self.charge(context)?;
        }
        let result = entry.session.execute(action, &context.stop).await;
        if result.is_err() && (opening || entry.session.is_closed()) {
            entry.session.close().await;
            self.remove(id)?;
        }
        let snapshot = result?;
        let Some(snapshot) = snapshot else {
            self.remove(id)?;
            return Ok(json!({"session_id":id,"closed":true,"untrusted":true}));
        };
        let original = {
            let mut original = entry.original.lock().map_err(|_| ErrorCode::Storage)?;
            let mut page = entry.page.lock().map_err(|_| ErrorCode::Storage)?;
            if let Some(destination) = destination {
                *original = destination;
            } else if page
                .as_ref()
                .is_some_and(|page| page.url != snapshot.metadata.url)
            {
                *original = PublicUrl::parse(&snapshot.metadata.url)?;
            }
            *page = Some(snapshot.metadata.clone());
            original.clone()
        };
        let rendered = self.fetcher.rendered(context, &original, &snapshot).await;
        // Opening must never leak an unreachable live session when evidence
        // publication fails before its ID can be returned to the client.
        let rendered = match rendered {
            Ok(record) => record,
            Err(error) => {
                entry.session.close().await;
                self.remove(id)?;
                return Err(error);
            }
        };
        let receipts = entry.broker.receipts()?;
        if context.stop.is_cancelled() {
            entry.session.close().await;
            self.remove(id)?;
            return Err(ErrorCode::Cancelled);
        }
        let mut links_truncated = rendered.links.len() > 8;
        let partial = rendered.error.is_some()
            || rendered.source.warnings.iter().any(|warning| {
                matches!(
                    warning,
                    crate::archive::SourceWarning::PartialExtraction
                        | crate::archive::SourceWarning::Truncated
                )
            });
        let links: Vec<_> = rendered
            .links
            .iter()
            .take(8)
            .map(|link| {
                let (label, truncated) = crate::provider::bounded_text(&link.label, 512);
                links_truncated |= truncated;
                json!({"url":link.url,"label":label})
            })
            .collect();
        Ok(
            json!({"session_id":id,"closed":false,"page":snapshot.metadata,
            "source":SourceBrief::from(&rendered.source),"dom_source_id":rendered.dom_source_id,
            "session_http_entities":receipts,"links":links,"links_truncated":links_truncated,
            "links_representation":rendered.source.representations.iter().find(|rep| rep.kind == crate::archive::RepresentationKind::Links),
            "error":rendered.error,"partial":partial,"untrusted":true}),
        )
    }

    pub async fn fetch(
        &self,
        context: &Context,
        url: &PublicUrl,
        profile: &Profile,
    ) -> Result<Value> {
        let mut value = self
            .execute(
                context,
                BrowserArgs::Open {
                    job_id: context.job,
                    url: url.as_str().into(),
                },
                profile,
            )
            .await?;
        let id = serde_json::from_value(value["session_id"].clone())
            .map_err(|_| ErrorCode::InvalidResponse)?;
        let entry = self.entry(context, id)?;
        entry.session.close().await;
        self.remove(id)?;
        // Closing joins late HTTP/archive work. Include those receipts too,
        // while keeping the snapshot's observed pending/error state intact.
        value["session_http_entities"] =
            serde_json::to_value(entry.broker.receipts()?).map_err(|_| ErrorCode::Storage)?;
        value["closed"] = Value::Bool(true);
        Ok(value)
    }

    fn charge(&self, context: &Context) -> Result<()> {
        self.ledger
            .reserve(
                context.owner,
                context.job,
                Charge {
                    browser_actions: 1,
                    ..Charge::default()
                },
            )?
            .finish(0, Some(0))
    }
}

#[cfg(test)]
mod tests {
    use crate::browser::profile::Profile;
    use crate::config::{Config, ProfilePolicy};

    use super::{session_settings, settings};

    #[test]
    fn session_settings_capture_one_profile_and_never_mutate_it_later() {
        let config = Config {
            browser: crate::config::BrowserConfig {
                profile: ProfilePolicy::ExitRegion,
                ..crate::config::BrowserConfig::default()
            },
            ..Config::default()
        };
        let base = settings(&config);
        assert_eq!(base.launch.locale, "en-US");
        // The profile is applied when a session is created.
        let germany = session_settings(&base, &Profile::for_region("DE").unwrap());
        assert_eq!(germany.launch.locale, "de-DE");
        assert_eq!(germany.launch.timezone, "Europe/Berlin");
        assert_eq!(germany.launch.accept_language, "de-DE,de;q=0.9,en;q=0.8");
        // Computing a later region's settings yields a different value but does
        // not rewrite the already-created session's captured profile.
        let france = session_settings(&base, &Profile::for_region("FR").unwrap());
        assert_eq!(france.launch.locale, "fr-FR");
        assert_eq!(germany.launch.locale, "de-DE");
        assert_eq!(germany.launch.timezone, "Europe/Berlin");
        assert_eq!(base.launch.locale, "en-US");
        germany.validate().unwrap();
        france.validate().unwrap();
    }
}
