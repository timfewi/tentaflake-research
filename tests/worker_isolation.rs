//! Explicit OS check: requires Linux user namespaces, Poppler's closure, and a
//! built research-worker. There is no silent skip or weakened sandbox fallback.

use secure_research::{
    error::ErrorCode,
    fetch::{IsolatedParser, Parser},
    policy::PublicUrl,
    provider::Context,
    worker::{self, DocumentKind, WorkerConfig},
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments
        .iter()
        .any(|a| a == "https://cleanup-denied.example/" || a == "--linger-denied")
    {
        for directory in ["/output/blocked", "/tmp/blocked"] {
            std::fs::create_dir(directory).unwrap();
            std::fs::write(format!("{directory}/evidence"), b"private").unwrap();
            std::fs::set_permissions(
                directory,
                std::os::unix::fs::PermissionsExt::from_mode(0o000),
            )
            .unwrap();
        }
        if arguments.iter().any(|a| a == "--linger-denied") {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        return;
    }
    if arguments.iter().any(|a| a == "--linger") {
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    if arguments.iter().any(|a| a == "--config") {
        let marker = arguments.windows(2).find(|w| w[0] == "--base-url").unwrap()[1].clone();
        let linger = if marker == "https://abort-denied.example/" {
            "--linger-denied"
        } else {
            "--linger"
        };
        let mut child = std::process::Command::new("/worker")
            .args([linger, &marker])
            .spawn()
            .unwrap();
        let _ = child.wait();
        return;
    }
    if arguments.get(1).is_some_and(|a| a == "--probe") {
        assert!(
            std::env::var("RESEARCH_TEST_SECRET").is_err(),
            "credential environment leaked"
        );
        assert!(
            std::fs::read(&arguments[2]).is_err(),
            "host file was visible"
        );
        assert_eq!(std::fs::read("/input").unwrap(), b"input-only");
        assert!(
            std::fs::write("/input", b"changed").is_err(),
            "input mount was writable"
        );
        assert!(
            std::net::TcpStream::connect_timeout(
                &arguments[3].parse().unwrap(),
                Duration::from_millis(200)
            )
            .is_err(),
            "host loopback was reachable"
        );
        assert!(!Path::new("/home").exists());
        assert!(!Path::new("/run/credentials").exists());
        assert!(!Path::new("/nix/var/nix/daemon-socket/socket").exists());
        std::fs::write("/output/probe-ok", b"ok").unwrap();
        std::fs::write("/tmp/scratch-probe", b"shared-quota").unwrap();
        for path in ["/escape", "/nix/escape", "/dev/escape"] {
            assert!(
                std::fs::write(path, b"unaccounted").is_err(),
                "writable auxiliary filesystem: {path}"
            );
        }
        std::fs::write("/dev/shm/shm-probe", b"shared-quota").unwrap();
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(check());
}

fn required(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("required test setting: {name}"))
}

/// Prefer an explicit pinned path, otherwise locate the binary in the parser
/// runtime closure. There is no fallback to a host tool.
fn parser_binary(env: &str, name: &str, closure: &[PathBuf]) -> PathBuf {
    if let Some(value) = std::env::var_os(env) {
        return PathBuf::from(value);
    }
    closure
        .iter()
        .filter(|root| name != "tesseract" || root.join("share/tessdata/eng.traineddata").is_file())
        .map(|root| root.join("bin").join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| {
            panic!("required test setting: {env} (or bin/{name} in RESEARCH_TEST_CLOSURE)")
        })
}

async fn check() {
    let store_paths: Vec<PathBuf> = std::fs::read_to_string(required("RESEARCH_TEST_CLOSURE"))
        .unwrap()
        .lines()
        .map(PathBuf::from)
        .collect();
    let config = WorkerConfig {
        executable: required("RESEARCH_TEST_WORKER"),
        bubblewrap: required("RESEARCH_TEST_BWRAP"),
        pdfinfo: required("RESEARCH_TEST_PDFINFO"),
        pdftotext: required("RESEARCH_TEST_PDFTOTEXT"),
        store_paths,
        ..Default::default()
    };
    config.validate().unwrap();
    let root = tempfile::tempdir().unwrap();
    let base = PublicUrl::parse("https://example.com/").unwrap();
    let stop = CancellationToken::new();
    let html = "<title>Fixture</title><p>Exact e\u{0301} 👩‍🔬 quote.</p>";
    let parsed = extract(
        &config,
        root.path(),
        html.as_bytes(),
        DocumentKind::Html,
        &base,
        1,
        &stop,
    )
    .await
    .unwrap();
    assert!(parsed.pages[0].contains("Exact e\u{0301} 👩‍🔬 quote."));
    assert_eq!(parsed.title, "Fixture");

    let streamed = r#"<main><template id="B:0"></template></main><div hidden id="S:0"><p>Streamed é 👩‍🔬 quote.</p><a href="/model">Model</a></div><div hidden>Hidden canary</div><script>$RC("B:0","S:0");throw new Error('must not run')</script>"#;
    let parsed = extract(
        &config,
        root.path(),
        streamed.as_bytes(),
        DocumentKind::Html,
        &base,
        1,
        &stop,
    )
    .await
    .unwrap();
    assert!(parsed.pages[0].contains("Streamed é 👩‍🔬 quote."));
    assert!(!parsed.pages[0].contains("Hidden canary"));
    assert!(
        parsed
            .warnings
            .contains(&worker::ExtractionWarning::StreamingHtmlRecovered)
    );
    let shell = format!(
        "<nav>{}</nav><main></main><footer>{}</footer><script src='/app.js'></script>",
        "Navigation ".repeat(50),
        "Footer ".repeat(50)
    );
    let parsed = extract(
        &config,
        root.path(),
        shell.as_bytes(),
        DocumentKind::Html,
        &base,
        1,
        &stop,
    )
    .await
    .unwrap();
    assert!(
        parsed
            .warnings
            .contains(&worker::ExtractionWarning::PageShell)
    );
    assert!(
        parsed
            .warnings
            .contains(&worker::ExtractionWarning::JavascriptRequired)
    );
    let challenge = format!(
        "<nav>{}</nav><main><div data-sitekey='captcha'>Verify you are human</div></main><script src='/challenge.js'></script>",
        "Navigation ".repeat(50)
    );
    assert!(matches!(
        extract(
            &config,
            root.path(),
            challenge.as_bytes(),
            DocumentKind::Html,
            &base,
            1,
            &stop
        )
        .await,
        Err(ErrorCode::AccessBlocked)
    ));

    let pdf = pdf_fixture();
    let info = worker::inspect_pdf(
        &config,
        root.path(),
        worker::ExtractionInput {
            bytes: &pdf,
            kind: DocumentKind::Pdf,
            base: &base,
            content_type: "application/pdf",
            max_pages: 2,
        },
        &stop,
    )
    .await
    .unwrap();
    assert_eq!(info.pages, 2);
    let parsed = extract(
        &config,
        root.path(),
        &pdf,
        DocumentKind::Pdf,
        &base,
        2,
        &stop,
    )
    .await
    .unwrap();
    assert_eq!(parsed.pages.len(), 2);
    assert!(parsed.pages[0].contains("First page"));
    assert!(parsed.pages[1].contains("Second page"));
    assert!(matches!(
        extract(
            &config,
            root.path(),
            &pdf,
            DocumentKind::Pdf,
            &base,
            1,
            &stop
        )
        .await,
        Err(ErrorCode::SizeLimit)
    ));
    assert!(matches!(
        extract(
            &config,
            root.path(),
            b"%PDF-broken",
            DocumentKind::Pdf,
            &base,
            2,
            &stop
        )
        .await,
        Err(ErrorCode::ExtractionFailed)
    ));
    assert_eq!(
        std::fs::read_dir(root.path()).unwrap().count(),
        0,
        "parser directories survived completion"
    );
    println!(
        "PASS isolated HTML/PDF extraction, page limits, corrupt PDF and temporary-file cleanup"
    );

    // Real, isolated OCR: a two-page image-only PDF with known per-page phrases.
    // poppler's pdftoppm builds the fixture from a normal text PDF (no
    // Python/ImageMagick needed) and also rasterizes inside the worker;
    // tesseract recognizes each page. The fixture is built, inspected and
    // checked against the disabled outcome before the recognizer is resolved,
    // so a missing recognizer is the only thing that can stop this section.
    let pdftoppm = parser_binary("RESEARCH_TEST_PDFTOPPM", "pdftoppm", &config.store_paths);
    let image_only = ocr_image_fixture(&pdftoppm);
    let info = worker::inspect_pdf(
        &config,
        root.path(),
        worker::ExtractionInput {
            bytes: &image_only,
            kind: DocumentKind::Pdf,
            base: &base,
            content_type: "application/pdf",
            max_pages: 2,
        },
        &stop,
    )
    .await
    .unwrap();
    assert_eq!(info.pages, 2, "image-only fixture page count");
    // The image-only PDF has no text layer: disabled OCR keeps the explicit
    // code and never fabricates text.
    assert!(matches!(
        extract(
            &config,
            root.path(),
            &image_only,
            DocumentKind::Pdf,
            &base,
            2,
            &stop
        )
        .await,
        Err(ErrorCode::OcrRequired)
    ));
    println!("PASS generated a two-page image-only PDF; isolated disabled OCR returns OcrRequired");
    let tesseract = parser_binary("RESEARCH_TEST_TESSERACT", "tesseract", &config.store_paths);
    let ocr_config = WorkerConfig {
        pdftoppm,
        tesseract,
        ocr: worker::OcrConfig {
            enabled: true,
            ..Default::default()
        },
        ..config.clone()
    };
    ocr_config.validate().unwrap();
    let parsed = extract(
        &ocr_config,
        root.path(),
        &image_only,
        DocumentKind::Pdf,
        &base,
        2,
        &stop,
    )
    .await
    .unwrap();
    assert_eq!(
        parsed.pages.len(),
        2,
        "OCR must preserve the PDF page count"
    );
    assert!(
        parsed.pages[0].contains("12345"),
        "OCR did not read page 1: {:?}",
        parsed.pages[0]
    );
    assert!(
        parsed.pages[1].contains("67890"),
        "OCR did not keep page 2 in order: {:?}",
        parsed.pages[1]
    );
    assert_eq!(parsed.extraction_version, "ocr/eng/v1");
    assert!(
        parsed
            .warnings
            .contains(&worker::ExtractionWarning::OcrApplied)
    );
    // The page cap bounds OCR while still preserving the full page count.
    let capped = WorkerConfig {
        ocr: worker::OcrConfig {
            enabled: true,
            pages: 1,
            ..Default::default()
        },
        ..ocr_config.clone()
    };
    let capped = extract(
        &capped,
        root.path(),
        &image_only,
        DocumentKind::Pdf,
        &base,
        2,
        &stop,
    )
    .await
    .unwrap();
    assert_eq!(capped.pages.len(), 2);
    assert!(capped.pages[0].contains("12345"));
    assert!(capped.pages[1].trim().is_empty());
    assert_eq!(
        std::fs::read_dir(root.path()).unwrap().count(),
        0,
        "OCR scratch survived completion"
    );
    println!(
        "PASS isolated OCR of an image-only PDF, page order/cap, disabled fallback and cleanup"
    );

    let secret = root.path().join("host-secret");
    std::fs::write(&secret, b"not-for-worker").unwrap();
    let input = root.path().join("input");
    std::fs::write(&input, b"input-only").unwrap();
    let output = root.path().join("output");
    std::fs::create_dir(&output).unwrap();
    let scratch = root.path().join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let canary = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let probe_config = WorkerConfig {
        executable: std::env::current_exe().unwrap(),
        ..config.clone()
    };
    let mut command = worker::sandbox(&probe_config, &input, &output, &scratch, &input).unwrap();
    command
        .env("RESEARCH_TEST_SECRET", "environment-canary")
        .args(["--", "/worker", "--probe"])
        .arg(&secret)
        .arg(canary.local_addr().unwrap().to_string());
    let status = tokio::time::timeout(Duration::from_secs(5), command.status())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success(), "OS boundary probe failed");
    assert_eq!(std::fs::read(output.join("probe-ok")).unwrap(), b"ok");
    assert_eq!(
        std::fs::read(scratch.join("shm-probe")).unwrap(),
        b"shared-quota"
    );
    assert_eq!(
        std::fs::read(scratch.join("scratch-probe")).unwrap(),
        b"shared-quota",
        "worker scratch escaped the supervised temporary filesystem"
    );
    println!(
        "PASS real mount/network namespace, read-only input and credential environment isolation"
    );

    let timeout_root = tempfile::tempdir().unwrap();
    let timeout_path = timeout_root.path().to_path_buf();
    let marker = format!("https://example.com/{}", uuid::Uuid::new_v4());
    let target = PublicUrl::parse(&marker).unwrap();
    let timeout_config = WorkerConfig {
        seconds: 2,
        ..probe_config
    };
    let task = tokio::spawn(async move {
        extract(
            &timeout_config,
            &timeout_path,
            b"input",
            DocumentKind::Html,
            &target,
            1,
            &CancellationToken::new(),
        )
        .await
    });
    let mut descendants = Vec::new();
    for _ in 0..30 {
        descendants = marked_processes(&marker);
        if !descendants.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(!descendants.is_empty(), "fixture descendant did not start");
    assert!(matches!(task.await.unwrap(), Err(ErrorCode::Timeout)));
    for _ in 0..30 {
        if descendants
            .iter()
            .all(|pid| !Path::new(&format!("/proc/{pid}")).exists())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        descendants
            .iter()
            .all(|pid| !Path::new(&format!("/proc/{pid}")).exists()),
        "parser descendants survived timeout"
    );
    assert_eq!(std::fs::read_dir(timeout_root.path()).unwrap().count(), 0);
    println!("PASS timeout kills and reaps observed descendants and removes temporary files");

    let aborted_root = tempfile::tempdir().unwrap();
    let parser = Arc::new(
        IsolatedParser::new(
            WorkerConfig {
                executable: std::env::current_exe().unwrap(),
                seconds: 5,
                ..config.clone()
            },
            aborted_root.path().to_path_buf(),
            1,
        )
        .unwrap(),
    );
    let running = parser.clone();
    let task = tokio::spawn(async move {
        let base = PublicUrl::parse("https://abort-denied.example/").unwrap();
        let context = Context {
            owner: 1001,
            job: uuid::Uuid::new_v4(),
            deadline: tokio::time::Instant::now() + Duration::from_secs(8),
            stop: CancellationToken::new(),
        };
        running
            .extract(
                &context,
                worker::ExtractionInput {
                    bytes: b"input",
                    kind: DocumentKind::Html,
                    base: &base,
                    content_type: "text/html",
                    max_pages: 1,
                },
            )
            .await
    });
    let mut blocked = false;
    for _ in 0..60 {
        blocked = std::fs::read_dir(aborted_root.path())
            .unwrap()
            .any(|entry| entry.unwrap().path().join("output/blocked").is_dir());
        if blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(blocked, "abort fixture did not create protected scratch");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    for _ in 0..60 {
        if std::fs::read_dir(aborted_root.path())
            .unwrap()
            .next()
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(
        std::fs::read_dir(aborted_root.path()).unwrap().count(),
        0,
        "aborted parser left protected scratch behind"
    );
    assert!(
        marked_processes("https://abort-denied.example/").is_empty(),
        "aborted parser descendant survived cleanup"
    );
    let base = PublicUrl::parse("https://abort-denied.example/").unwrap();
    let context = Context {
        owner: 1001,
        job: uuid::Uuid::new_v4(),
        deadline: tokio::time::Instant::now() + Duration::from_secs(3),
        stop: CancellationToken::new(),
    };
    let oversized_type = "x".repeat(257);
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            parser.inspect(
                &context,
                worker::ExtractionInput {
                    bytes: b"input",
                    kind: DocumentKind::Html,
                    base: &base,
                    content_type: &oversized_type,
                    max_pages: 1,
                },
            )
        )
        .await
        .unwrap(),
        Err(ErrorCode::InvalidRequest)
    ));
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            parser.inspect(
                &context,
                worker::ExtractionInput {
                    bytes: b"input",
                    kind: DocumentKind::Html,
                    base: &base,
                    content_type: "text/html",
                    max_pages: 1,
                },
            )
        )
        .await
        .unwrap(),
        Err(ErrorCode::InvalidRequest)
    ));
    println!("PASS direct parser-future abort reaps the worker and clears protected scratch");

    let denied_root = tempfile::tempdir().unwrap();
    let denied = PublicUrl::parse("https://cleanup-denied.example/").unwrap();
    let denied_config = WorkerConfig {
        executable: std::env::current_exe().unwrap(),
        ..config
    };
    assert!(matches!(
        extract(
            &denied_config,
            denied_root.path(),
            b"input",
            DocumentKind::Html,
            &denied,
            1,
            &CancellationToken::new(),
        )
        .await,
        Err(ErrorCode::Storage)
    ));
    assert_eq!(std::fs::read_dir(denied_root.path()).unwrap().count(), 0);
    println!("PASS parser worker permission denial leaves no temporary evidence");
}

async fn extract(
    config: &WorkerConfig,
    temporary: &Path,
    bytes: &[u8],
    kind: DocumentKind,
    base: &PublicUrl,
    max_pages: u32,
    stop: &CancellationToken,
) -> secure_research::error::Result<worker::ParsedDocument> {
    let input = worker::ExtractionInput {
        bytes,
        kind,
        base,
        content_type: match kind {
            DocumentKind::Html => "text/html; charset=utf-8",
            DocumentKind::Pdf => "application/pdf",
            DocumentKind::Text => "text/plain",
        },
        max_pages,
    };
    worker::extract(config, temporary, input, stop).await
}

fn marked_processes(marker: &str) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let pid = entry.file_name().to_str()?.parse().ok()?;
            let bytes = std::fs::read(entry.path().join("cmdline")).ok()?;
            (bytes
                .split(|b| *b == 0)
                .any(|arg| arg == b"--linger" || arg == b"--linger-denied")
                && bytes.windows(marker.len()).any(|w| w == marker.as_bytes()))
            .then_some(pid)
        })
        .collect()
}

fn pdf_fixture() -> Vec<u8> {
    let first = "BT /F1 12 Tf 72 720 Td (First page) Tj ET\n";
    let second = "BT /F1 12 Tf 72 720 Td (Second page) Tj ET\n";
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>".to_owned(),
        format!("<< /Length {} >>\nstream\n{first}endstream", first.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>".to_owned(),
        format!("<< /Length {} >>\nstream\n{second}endstream", second.len()),
    ];
    assemble_pdf(&objects)
}

/// Small text PDF used only to build the image-only OCR fixture.
fn text_pdf(pages: &[&str]) -> Vec<u8> {
    let count = pages.len();
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        format!(
            "<< /Type /Pages /Kids [{}] /Count {count} >>",
            (0..count)
                .map(|index| format!("{} 0 R", 3 + index))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    ];
    for index in 0..count {
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {} 0 R >> >> /Contents {} 0 R >>",
            3 + 2 * count,
            3 + count + index
        ));
    }
    for text in pages {
        let stream = format!("BT /F1 48 Tf 72 400 Td ({text}) Tj ET\n");
        objects.push(format!(
            "<< /Length {} >>\nstream\n{stream}endstream",
            stream.len()
        ));
    }
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned());
    assemble_pdf(&objects)
}

fn assemble_pdf(objects: &[String]) -> Vec<u8> {
    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{object}\nendobj\n", index + 1));
    }
    let xref = pdf.len();
    pdf.push_str(&format!(
        "xref\n0 {}\n0000000000 65535 f \n",
        objects.len() + 1
    ));
    for offset in offsets {
        pdf.push_str(&format!("{offset:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    ));
    pdf.into_bytes()
}

/// Build a two-page image-only PDF with the known phrases `OCR FIXTURE 12345`
/// and `SECOND PAGE 67890`. A text PDF is rasterized to JPEG by the pinned
/// `pdftoppm`, then each page is wrapped as a full-page `DCTDecode` image. No
/// host tools beyond the parser closure are used, and the result has no
/// extractable text layer.
fn ocr_image_fixture(pdftoppm: &Path) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    let text = directory.path().join("text.pdf");
    std::fs::write(&text, text_pdf(&["OCR FIXTURE 12345", "SECOND PAGE 67890"])).unwrap();
    let prefix = directory.path().join("page");
    let status = std::process::Command::new(pdftoppm)
        .args(["-r", "200", "-jpeg", "-f", "1", "-l", "2"])
        .arg(&text)
        .arg(&prefix)
        .status()
        .unwrap();
    assert!(status.success(), "fixture rasterization failed");
    let images = ["page-1.jpg", "page-2.jpg"]
        .map(|name| std::fs::read(directory.path().join(name)).unwrap());
    image_only_pdf(&images)
}

/// Wrap each JPEG as one full-page image XObject, one PDF page per image.
fn image_only_pdf(images: &[Vec<u8>]) -> Vec<u8> {
    let count = images.len();
    let mut parts: Vec<Vec<u8>> = vec![
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_vec(),
        format!(
            "2 0 obj\n<< /Type /Pages /Kids [{}] /Count {count} >>\nendobj\n",
            (0..count)
                .map(|index| format!("{} 0 R", 3 + index))
                .collect::<Vec<_>>()
                .join(" ")
        )
        .into_bytes(),
    ];
    for index in 0..count {
        parts.push(
            format!(
                "{} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im0 {} 0 R >> >> /Contents {} 0 R >>\nendobj\n",
                3 + index,
                3 + 2 * count + index,
                3 + count + index
            )
            .into_bytes(),
        );
    }
    let content = b"q 612 0 0 792 0 0 cm /Im0 Do Q";
    for index in 0..count {
        let mut object = format!(
            "{} 0 obj\n<< /Length {} >>\nstream\n",
            3 + count + index,
            content.len()
        )
        .into_bytes();
        object.extend_from_slice(content);
        object.extend_from_slice(b"\nendstream\nendobj\n");
        parts.push(object);
    }
    for (index, jpeg) in images.iter().enumerate() {
        let (width, height, components) = jpeg_dimensions(jpeg);
        let color_space = match components {
            1 => "/DeviceGray",
            3 => "/DeviceRGB",
            4 => "/DeviceCMYK",
            other => panic!("unsupported JPEG component count: {other}"),
        };
        let header = format!(
            "<< /Type /XObject /Subtype /Image /Width {width} /Height {height} /ColorSpace {color_space} /BitsPerComponent 8 /Filter /DCTDecode /Length {} >>",
            jpeg.len()
        );
        let mut object =
            format!("{} 0 obj\n{header}\nstream\n", 3 + 2 * count + index).into_bytes();
        object.extend_from_slice(jpeg);
        object.extend_from_slice(b"\nendstream\nendobj\n");
        parts.push(object);
    }
    let mut pdf = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for part in &parts {
        offsets.push(pdf.len());
        pdf.extend_from_slice(part);
    }
    let xref = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", parts.len() + 1).as_bytes());
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            parts.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

/// Minimal baseline-JPEG SOF scan for dimensions and component count.
fn jpeg_dimensions(jpeg: &[u8]) -> (u16, u16, u8) {
    let mut index = 2;
    while index + 1 < jpeg.len() {
        if jpeg[index] != 0xFF {
            index += 1;
            continue;
        }
        let marker = jpeg[index + 1];
        index += 2;
        if matches!(marker, 0xD8 | 0xD9 | 0x01 | 0xD0..=0xD7) {
            continue;
        }
        if index + 2 > jpeg.len() {
            break;
        }
        let length = u16::from_be_bytes([jpeg[index], jpeg[index + 1]]) as usize;
        if (0xC0..=0xC3).contains(&marker) {
            assert!(length >= 8 && index + 7 < jpeg.len());
            let height = u16::from_be_bytes([jpeg[index + 3], jpeg[index + 4]]);
            let width = u16::from_be_bytes([jpeg[index + 5], jpeg[index + 6]]);
            return (width, height, jpeg[index + 7]);
        }
        index += length;
    }
    panic!("JPEG SOF marker not found");
}
