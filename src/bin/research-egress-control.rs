use clap::Parser;
use secure_research::egress::{LeaseReadError, control_state_diagnostic};
use secure_research::egress_control::{Controller, lock_output, protected_parent, publish};
use secure_research::error::{ErrorCode, Result};
use secure_research::{diagnostics, diagnostics::Component, diagnostics::Event};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser)]
struct Args {
    /// Root-owned observation lease from the operator's VPN/firewall adapter.
    #[arg(long)]
    input: PathBuf,
    /// Research-specific lease; its existing directory must be root-controlled.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 60)]
    drain_seconds: u64,
}

fn main() {
    if let Err(error) = run() {
        diagnostics::emit_error(Component::EgressControl, error);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if args.input == args.output {
        return Err(ErrorCode::InvalidRequest);
    }
    protected_parent(&args.input)?;
    let _lock = lock_output(&args.output)?;
    let mut controller = Controller::new(args.drain_seconds)?;
    // Invalidate any predecessor's lease before accepting new observations.
    let initial = controller.update(None, chrono::Utc::now().timestamp(), Instant::now());
    publish(&args.output, &initial)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ErrorCode::WorkerFailed)?
        .block_on(async move {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| ErrorCode::WorkerFailed)?;
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut input_issue = None;
            let mut output_generation = initial.generation;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let input = if protected_parent(&args.input).is_err() {
                            let issue = LeaseReadError::Invalid;
                            if input_issue != Some(issue) {
                                diagnostics::emit(Component::EgressControl, observation_event(issue));
                                input_issue = Some(issue);
                            }
                            None
                        } else {
                            match control_state_diagnostic(&args.input) {
                                Ok(state) => {
                                    input_issue = None;
                                    Some(state)
                                }
                                Err(issue) => {
                                    if input_issue != Some(issue) {
                                        diagnostics::emit(Component::EgressControl, observation_event(issue));
                                        input_issue = Some(issue);
                                    }
                                    None
                                }
                            }
                        };
                        let next = controller.update(input, chrono::Utc::now().timestamp(), Instant::now());
                        if next.generation != output_generation {
                            diagnostics::emit(Component::EgressControl, Event::GenerationChanged);
                            output_generation = next.generation;
                        }
                        publish(&args.output, &next)?;
                    }
                    _ = term.recv() => break,
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
            publish(&args.output, &controller.update(None, chrono::Utc::now().timestamp(), Instant::now()))
        })
}

fn observation_event(issue: LeaseReadError) -> Event {
    match issue {
        LeaseReadError::Unavailable => Event::ObservationLeaseUnavailable,
        LeaseReadError::Invalid => Event::ObservationLeaseInvalid,
        LeaseReadError::Expired => Event::ObservationLeaseExpired,
    }
}
