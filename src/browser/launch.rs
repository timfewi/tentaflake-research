use super::cdp::{Cdp, Event};
use crate::{
    config::{MAX_HTTP_BODY_BYTES, MIB},
    error::{ErrorCode, Result},
};
use chromiumoxide::browser::BrowserConfig;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, process::Child, sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

fn default_locale() -> String {
    super::profile::Profile::neutral().locale
}

fn default_timezone() -> String {
    super::profile::Profile::neutral().timezone
}

fn default_accept_language() -> String {
    super::profile::Profile::neutral().accept_language
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub chromium: PathBuf,
    pub width: u32,
    pub height: u32,
    pub operation_seconds: u64,
    pub html_bytes: u64,
    pub requests: u32,
    pub actions: u32,
    /// Coherent per-session profile, fixed when the session starts. Defaults
    /// keep older serialized settings valid without a region-aware profile.
    #[serde(default = "default_locale")]
    pub locale: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default = "default_accept_language")]
    pub accept_language: String,
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        super::profile::Profile {
            locale: self.locale.clone(),
            timezone: self.timezone.clone(),
            accept_language: self.accept_language.clone(),
        }
        .validate()?;
        if !self.chromium.is_absolute()
            || !(640..=3840).contains(&self.width)
            || !(480..=2160).contains(&self.height)
            || !(1..=120).contains(&self.operation_seconds)
            || !(MIB..=MAX_HTTP_BODY_BYTES).contains(&self.html_bytes)
            || !(1..=4096).contains(&self.requests)
            || !(1..=256).contains(&self.actions)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

pub struct Launched {
    pub child: Child,
    pub cdp: Arc<Cdp>,
    stderr: JoinHandle<()>,
}

impl Launched {
    pub async fn start(
        settings: &Settings,
        stop: &CancellationToken,
    ) -> Result<(Self, mpsc::Receiver<Event>)> {
        settings.validate()?;
        // The caller is already inside the private root/PID/network namespace.
        // Do not add no-sandbox or automation-concealment switches here.
        let config = BrowserConfig::builder()
            .chrome_executable(&settings.chromium)
            .user_data_dir("/scratch/profile")
            .window_size(settings.width, settings.height)
            .new_headless_mode()
            // Defense for a future high-level chromiumoxide handler. Our
            // launch-only path does not consume this handler setting: actual
            // upstream certificate verification lives in http::tls_config
            // while browser requests go through the intercepted transport.
            .respect_https_errors()
            .disable_default_args()
            .args([
                "no-first-run", "no-default-browser-check", "no-startup-window",
                "disable-background-networking", "disable-component-update",
                "disable-component-extensions-with-background-pages",
                "disable-sync", "disable-breakpad", "disable-quic",
                "disable-dev-shm-usage", "disable-default-apps",
            ])
            // ArgsBuilder adds the prefix and joins values itself. Keep keys
            // separate from values so future defaults merge by the real key.
            .args([
                ("disable-features", "MediaRouter,OptimizationHints,AutofillServerCommunication,HttpsUpgrades,HttpsFirstBalancedModeAutoEnable"),
                ("force-webrtc-ip-handling-policy", "disable_non_proxied_udp"),
                ("proxy-server", "http://127.0.0.1:9"),
                ("proxy-bypass-list", "<-loopback>"),
                ("host-resolver-rules", "MAP * ~NOTFOUND"),
                ("lang", settings.locale.as_str()),
                ("accept-lang", settings.accept_language.as_str()),
            ])
            .build().map_err(|_| ErrorCode::InvalidRequest)?;
        let mut child = config
            .launch()
            .map_err(|_| ErrorCode::WorkerFailed)?
            .into_inner();
        // Chromiumoxide sets kill_on_drop on its Tokio command before spawning;
        // into_inner preserves that process handle and restores Tokio stderr.
        let mut stderr = child.stderr.take().ok_or(ErrorCode::WorkerFailed)?;
        let endpoint = tokio::select! {
            biased;
            _ = stop.cancelled() => Err(ErrorCode::Cancelled),
            result = tokio::time::timeout(Duration::from_secs(15), async {
                let mut line = Vec::new();
                let mut total = 0;
                loop {
                    let byte = stderr.read_u8().await.map_err(|_| ErrorCode::WorkerFailed)?;
                    total += 1;
                    if total > 1024*1024 || line.len() >= 8192 { return Err(ErrorCode::SizeLimit); }
                    if byte == b'\n' {
                        if let Some(endpoint) = line.strip_prefix(b"DevTools listening on ") {
                            return String::from_utf8(endpoint.to_vec()).map_err(|_| ErrorCode::WorkerFailed);
                        }
                        line.clear();
                    } else { line.push(byte); }
                }
            }) => result.unwrap_or(Err(ErrorCode::Timeout)),
        };
        let endpoint = match endpoint {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
        };
        let (cdp, events) = match Cdp::connect(
            &endpoint,
            Duration::from_secs(settings.operation_seconds),
            stop.clone(),
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
        };
        let child_stop = cdp.stopped();
        let stderr = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let mut total = 0_u64;
            loop {
                let read = tokio::select! { _ = child_stop.cancelled() => break, read = stderr.read(&mut buffer) => read };
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(count) => total += count as u64,
                }
                if total > 8 * MIB {
                    child_stop.cancel();
                    break;
                }
            }
        });
        Ok((Self { child, cdp, stderr }, events))
    }

    pub async fn close(mut self) {
        self.cdp.close().await;
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        let _ = self.stderr.await;
    }
}
