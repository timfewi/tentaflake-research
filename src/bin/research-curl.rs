//! A deliberately narrow GET-only curl replacement backed by Research evidence.
//! It has no network transport of its own and cannot set request headers.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{
    ArgAction, Parser,
    error::{ContextKind, ContextValue, ErrorKind},
};
use secure_research::{
    bridge::Bridge,
    config::{MAX_HTTP_BODY_BYTES, MAX_JOB_SECONDS, MAX_REPORT_BYTES},
    policy::{PublicUrl, sha256},
    protocol::{ReportChunk, Tool},
};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Shown by `--help` and after an unsupported option, so both state one contract.
const CONTRACT: &str = "\
research-curl is a GET-only client backed by the Secure Research service, not full curl.
It has no network access of its own and sends no custom headers, credentials,
methods or bodies. The response body goes to stdout; redirect it to save a file:

  research-curl -fsSL --max-time 25 https://example.com/ > page.html

Not available: response headers (-D, -I), output files (-o, -O), request headers
(-H), methods and bodies (-X, -d, -F, -T), credentials (-u) and TLS options.
Response headers are not retained. When the Research MCP tools are exposed, use
research_fetch and research_read for a source's final URL and retrieval time.";

const SUPPORTED_OPTIONS: &str = "-f/--fail, -s/--silent, -S/--show-error, -L/--location, \
-m/--max-time SECONDS, --socket PATH, -h/--help, -V/--version";

#[derive(Parser)]
#[command(
    name = "research-curl",
    bin_name = "research-curl",
    version,
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        "\nGET-only client backed by the Secure Research service; not curl.\n",
        "Supported options: -f -s -S -L -m/--max-time --socket"
    ),
    about = "GET a public URL through the Secure Research service (restricted curl replacement)",
    after_help = CONTRACT
)]
struct Args {
    /// Service socket; defaults to $RESEARCH_SOCKET.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Accepted for compatibility; HTTP failures are always errors.
    #[arg(short = 'f', long = "fail", action = ArgAction::SetTrue)]
    fail: bool,
    /// Suppress error text; the exit status still reports failure.
    #[arg(short = 's', long = "silent", action = ArgAction::SetTrue)]
    silent: bool,
    /// Show error text even with --silent.
    #[arg(short = 'S', long = "show-error", action = ArgAction::SetTrue)]
    show_error: bool,
    /// Accepted for compatibility; redirects follow the service policy.
    #[arg(short = 'L', long = "location", action = ArgAction::SetTrue)]
    location: bool,
    /// Whole-second deadline for the transfer.
    #[arg(short = 'm', long = "max-time")]
    max_time: Option<u64>,
    /// Public HTTP(S) URL to GET.
    url: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Parsing, help and version never open the socket or start a job.
    let args = Args::try_parse().unwrap_or_else(|error| match unsupported_option(&error) {
        Some(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
        None => error.exit(),
    });
    let show_error = !args.silent || args.show_error;
    if let Err(error) = run(args).await {
        if show_error {
            eprintln!("research-curl: {error:#}");
        }
        std::process::exit(1);
    }
}

/// Replaces clap's generic unknown-argument error, whose tip suggests passing
/// the rejected curl option after `--` as if it were the URL. Only the option
/// name is echoed: a value (for example a header) never reaches the diagnostic.
fn unsupported_option(error: &clap::Error) -> Option<String> {
    if error.kind() != ErrorKind::UnknownArgument {
        return None;
    }
    let Some(ContextValue::String(argument)) = error.get(ContextKind::InvalidArg) else {
        return None;
    };
    let headline = match argument
        .split('=')
        .next()
        .filter(|name| name.starts_with('-'))
    {
        Some(name) => format!("research-curl: unsupported option '{name}'"),
        None => "research-curl: only one URL is supported".to_owned(),
    };
    Some(format!(
        "{headline}\n\n{CONTRACT}\n\nSupported options: {SUPPORTED_OPTIONS}\nRun 'research-curl --help' to check the installed contract."
    ))
}

async fn run(args: Args) -> Result<()> {
    if let Some(seconds) = args.max_time {
        ensure!(
            (1..=MAX_JOB_SECONDS).contains(&seconds),
            "--max-time must be between 1 and {MAX_JOB_SECONDS} seconds"
        );
        tokio::time::timeout(Duration::from_secs(seconds), run_with_args(args))
            .await
            .context("Research request timed out")?
    } else {
        run_with_args(args).await
    }
}

async fn run_with_args(args: Args) -> Result<()> {
    let socket = args
        .socket
        .or_else(|| std::env::var_os("RESEARCH_SOCKET").map(PathBuf::from))
        .context("RESEARCH_SOCKET or --socket is required")?;
    // Redirects are policy-checked by the service and failures are always errors.
    // -s/-S are handled by main; this CLI never emits a progress meter.
    let _compatible_flags = (args.fail, args.location);
    let url = PublicUrl::parse(&args.url)
        .context("only public HTTP(S) URLs are supported")?
        .request_url();
    let bridge = Bridge::connect_with_retry(&socket).await?;
    let job = bridge
        .call(
            Tool::ResearchJob,
            json!({"operation":"start","limits":{"micro_usd":0,"queries":0,"browser_actions":0}}),
            CancellationToken::new(),
        )
        .await?;
    let job_id = job["job"]["id"]
        .as_str()
        .context("Research did not return a job ID")?
        .to_owned();
    let result = fetch_body(&bridge, &job_id, url.as_str()).await;
    let finish = bridge
        .call(
            Tool::ResearchJob,
            json!({"operation":"finish","job_id":job_id}),
            CancellationToken::new(),
        )
        .await;
    bridge.close().await;
    result?;
    finish?;
    Ok(())
}

async fn fetch_body(bridge: &Bridge, job_id: &str, url: &str) -> Result<()> {
    let fetch = bridge
        .call(
            Tool::ResearchFetch,
            json!({"job_id":job_id,"urls":[url],"mode":"http"}),
            CancellationToken::new(),
        )
        .await?;
    let fetch = complete_report(bridge, fetch).await?;
    let item = fetch["items"]
        .get(0)
        .context("Research returned no fetch result")?;
    // Extraction runs after the complete HTTP entity is retained. A missing or
    // failed parser does not invalidate that body; access and policy failures do.
    let extraction_only_error = matches!(
        item["error"].as_str(),
        Some("extraction_failed" | "provider_unavailable")
    );
    ensure!(
        (item["state"] == "success" && item["error"].is_null())
            || (item["state"] == "partial" && (item["error"].is_null() || extraction_only_error)),
        "Research fetch failed: state={}, error={}",
        item["state"],
        item["error"]
    );
    let source_id = item["data"]["raw_source_id"]
        .as_str()
        .context("Research returned no raw source")?;
    let metadata = bridge
        .call(
            Tool::ResearchRead,
            json!({"kind":"metadata","source_id":source_id}),
            CancellationToken::new(),
        )
        .await?;
    let metadata = complete_report(bridge, metadata).await?;
    let representation_id = raw_representation_id(&metadata)?;
    let mut cursor: Option<String> = None;
    let mut written = 0_u64;
    let mut total = None;
    let mut stdout = tokio::io::stdout();
    loop {
        let chunk = bridge
            .call(
                Tool::ResearchRead,
                json!({"kind":"source","source_id":source_id,"representation_id":representation_id,"cursor":cursor}),
                CancellationToken::new(),
            )
            .await?;
        let chunk = complete_report(bridge, chunk).await?;
        let (bytes, next) = body_chunk(&chunk, written, &mut total)?;
        stdout.write_all(&bytes).await?;
        written += bytes.len() as u64;
        cursor = next;
        if cursor.is_none() {
            break;
        }
    }
    stdout.flush().await?;
    Ok(())
}

fn body_chunk(
    chunk: &Value,
    start: u64,
    expected_total: &mut Option<u64>,
) -> Result<(Vec<u8>, Option<String>)> {
    ensure!(
        chunk["encoding"] == "base64_bytes",
        "raw evidence encoding changed"
    );
    let bytes = STANDARD.decode(
        chunk["content"]
            .as_str()
            .context("Research returned no chunk content")?,
    )?;
    let total = chunk["total"]
        .as_u64()
        .context("Research returned no body size")?;
    // HTTP fetches are limited by pdf_bytes, whose operator ceiling is 32 MiB.
    ensure!(
        total <= MAX_HTTP_BODY_BYTES,
        "Research body exceeds the HTTP maximum"
    );
    let end = start
        .checked_add(bytes.len() as u64)
        .context("Research body size overflowed")?;
    ensure!(
        chunk["start"].as_u64() == Some(start)
            && chunk["end"].as_u64() == Some(end)
            && end <= total
            && expected_total.is_none_or(|previous| previous == total),
        "Research returned a non-contiguous body"
    );
    let next = chunk["next_cursor"].as_str().map(str::to_owned);
    ensure!(
        (next.is_some() && !bytes.is_empty() && end < total) || (next.is_none() && end == total),
        "Research returned a stalled or incomplete body cursor"
    );
    *expected_total = Some(total);
    Ok((bytes, next))
}

/// Tool replies above the configured result limit are retained as short-lived
/// reports. Read the exact JSON before following any source or cursor it names.
async fn complete_report(bridge: &Bridge, reply: Value) -> Result<Value> {
    let Some(report_id) = reply["report_id"].as_str() else {
        return Ok(reply);
    };
    let report_id = Uuid::parse_str(report_id).context("Research returned an invalid report ID")?;
    ensure!(
        reply["truncated"] == true && reply["encoding"] == "json",
        "Research returned an invalid report reference"
    );
    let bytes = reply["report_bytes"]
        .as_u64()
        .context("Research returned no report size")?;
    ensure!(
        (1..=MAX_REPORT_BYTES).contains(&bytes),
        "Research report exceeds the configured maximum"
    );
    let mut text = String::new();
    let mut start = 0_u64;
    let mut total = None;
    let mut digest: Option<String> = None;
    loop {
        let chunk: ReportChunk = serde_json::from_value(
            bridge
                .call(
                    Tool::ResearchRead,
                    json!({"kind":"report","report_id":report_id,"start":start}),
                    CancellationToken::new(),
                )
                .await?,
        )
        .context("Research returned an invalid report chunk")?;
        ensure!(
            chunk.report_id == report_id
                && chunk.encoding == "json_utf8_characters"
                && chunk.start == start
                && chunk.end == start + chunk.content.chars().count() as u64
                && chunk.end <= chunk.total
                && total.is_none_or(|previous| previous == chunk.total)
                && digest
                    .as_deref()
                    .is_none_or(|previous| previous == chunk.sha256)
                && text.len().saturating_add(chunk.content.len()) <= bytes as usize,
            "Research returned a non-contiguous report"
        );
        total = Some(chunk.total);
        digest = Some(chunk.sha256);
        text.push_str(&chunk.content);
        if let Some(next) = chunk.next_start {
            ensure!(
                next == chunk.end && next > start && next < chunk.total,
                "Research returned a stalled report cursor"
            );
            start = next;
        } else {
            ensure!(chunk.end == chunk.total, "Research report was incomplete");
            break;
        }
    }
    let actual_digest = sha256(text.as_bytes());
    ensure!(
        text.len() == bytes as usize && digest.as_deref() == Some(actual_digest.as_str()),
        "Research report integrity check failed"
    );
    serde_json::from_str(&text).context("Research returned invalid report JSON")
}

fn raw_representation_id(metadata: &Value) -> Result<&str> {
    metadata["representations"]
        .as_array()
        .context("Research returned no representations")?
        .iter()
        .find(|representation| representation["kind"] == "http_entity")
        .and_then(|representation| representation["id"].as_str())
        .ok_or_else(|| anyhow::anyhow!("Research did not retain a raw HTTP body"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn rejected(arguments: &[&str]) -> String {
        let error = Args::try_parse_from(arguments)
            .err()
            .expect("arguments are rejected");
        unsupported_option(&error).expect("a curl-specific diagnostic")
    }

    #[test]
    fn unsupported_curl_options_get_an_actionable_contract() {
        for option in ["-D", "-o", "-H", "--header"] {
            let message = rejected(&["research-curl", option, "value", "https://example.com/"]);
            assert!(message.contains(&format!("unsupported option '{option}'")));
            assert!(message.contains("GET-only"), "{message}");
            assert!(message.contains("not full curl"), "{message}");
            assert!(message.contains("> page.html"), "{message}");
            assert!(message.contains("response headers"), "{message}");
            assert!(
                !message.contains("to pass") && !message.contains("-- -"),
                "{message}"
            );
        }
    }

    #[test]
    fn diagnostics_never_echo_option_values_or_extra_urls() {
        let message = rejected(&[
            "research-curl",
            "--header=Authorization: secret",
            "https://x.example/",
        ]);
        assert!(message.contains("unsupported option '--header'"));
        assert!(!message.contains("secret"));
        let message = rejected(&[
            "research-curl",
            "https://a.example/",
            "https://b.example/?token=1",
        ]);
        assert!(message.contains("only one URL"));
        assert!(!message.contains("token"));
    }

    #[test]
    fn supported_option_list_covers_every_declared_option() {
        let command = Args::command();
        for argument in command
            .get_arguments()
            .filter(|argument| !argument.is_positional())
        {
            let long = argument.get_long().expect("every option has a long name");
            assert!(SUPPORTED_OPTIONS.contains(&format!("--{long}")), "{long}");
            if let Some(short) = argument.get_short() {
                assert!(SUPPORTED_OPTIONS.contains(&format!("-{short}")), "{short}");
            }
        }
    }

    #[test]
    fn help_and_version_are_ordinary_clap_outputs_not_diagnostics() {
        for flag in ["--help", "-V", "--version"] {
            let error = Args::try_parse_from(["research-curl", flag]).err().unwrap();
            assert!(unsupported_option(&error).is_none(), "{flag}");
        }
        let version = Args::command().render_long_version();
        assert!(
            version.starts_with(&format!("research-curl {}\n", env!("CARGO_PKG_VERSION"))),
            "{version}"
        );
        assert!(version.contains("not curl"));
    }

    #[test]
    fn selects_only_raw_http_evidence() -> Result<()> {
        let source = json!({"representations":[
            {"kind":"text","id":"derived"},
            {"kind":"http_entity","id":"raw"}
        ]});
        ensure!(raw_representation_id(&source)? == "raw");
        ensure!(
            raw_representation_id(&json!({"representations":[{"kind":"text","id":"derived"}]}))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn body_chunks_must_advance_toward_one_fixed_total() -> Result<()> {
        let mut total = None;
        let first = json!({"encoding":"base64_bytes","content":"YQ==","start":0,"end":1,"total":2,"next_cursor":"next"});
        assert_eq!(
            body_chunk(&first, 0, &mut total)?,
            (b"a".to_vec(), Some("next".into()))
        );
        let stalled = json!({"encoding":"base64_bytes","content":"","start":1,"end":1,"total":2,"next_cursor":"next"});
        assert!(body_chunk(&stalled, 1, &mut total).is_err());
        let changed_total = json!({"encoding":"base64_bytes","content":"Yg==","start":1,"end":2,"total":3,"next_cursor":"more"});
        assert!(body_chunk(&changed_total, 1, &mut total).is_err());
        let oversized = json!({"encoding":"base64_bytes","content":"Yg==","start":1,"end":2,"total":MAX_HTTP_BODY_BYTES + 1,"next_cursor":"more"});
        assert!(body_chunk(&oversized, 1, &mut total).is_err());
        let final_chunk = json!({"encoding":"base64_bytes","content":"Yg==","start":1,"end":2,"total":2,"next_cursor":null});
        assert_eq!(
            body_chunk(&final_chunk, 1, &mut total)?,
            (b"b".to_vec(), None)
        );
        Ok(())
    }
}
