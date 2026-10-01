use clap::Parser;
use secure_research::{
    config::{MAX_HTTP_BODY_BYTES, MAX_PDF_PAGES, MIB},
    error::{ErrorCode, Result},
    policy::PublicUrl,
    worker::{self, DocumentKind, WorkerConfig},
};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long, value_enum)]
    kind: DocumentKind,
    #[arg(long)]
    base_url: String,
    #[arg(long)]
    content_type: String,
    #[arg(long)]
    max_pages: u32,
    #[arg(long)]
    inspect: bool,
}

fn main() {
    if let Err(error) = run() {
        std::process::exit(worker::worker_exit(error));
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let bytes = worker::read_bounded(&args.config, MIB)?;
    let config: WorkerConfig =
        serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    config.validate()?;
    worker::set_parser_limits(&config)?;
    if args.max_pages == 0 || args.max_pages > MAX_PDF_PAGES {
        return Err(ErrorCode::InvalidRequest);
    }
    let input = worker::read_bounded(Path::new("/input"), MAX_HTTP_BODY_BYTES)?;
    let base = PublicUrl::parse(&args.base_url)?;
    if args.inspect {
        if !matches!(args.kind, DocumentKind::Pdf) {
            return Err(ErrorCode::InvalidRequest);
        }
        let info = worker::pdf_info(&config, Path::new("/input"), args.max_pages)?;
        return write_result(&serde_json::to_vec(&info).map_err(|_| ErrorCode::ExtractionFailed)?);
    }
    let parsed = match args.kind {
        DocumentKind::Html => worker::parse_html(&input, &base, &args.content_type)?,
        DocumentKind::Text => worker::parse_text(&input, &args.content_type)?,
        DocumentKind::Pdf => worker::parse_pdf(
            &config,
            Path::new("/input"),
            Path::new("/output/text"),
            args.max_pages,
        )?,
    };
    parsed.validate(args.max_pages, config.output_bytes)?;
    let bytes = serde_json::to_vec(&parsed).map_err(|_| ErrorCode::ExtractionFailed)?;
    if bytes.len() as u64 > config.output_bytes {
        return Err(ErrorCode::SizeLimit);
    }
    write_result(&bytes)
}

fn write_result(bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open("/output/result.json")
        .map_err(|_| ErrorCode::Storage)?;
    file.write_all(bytes).map_err(|_| ErrorCode::Storage)
}
