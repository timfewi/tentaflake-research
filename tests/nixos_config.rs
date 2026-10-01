//! Decode the actual JSON emitted by the synthetic NixOS module fixture with
//! production schemas. This never starts a service or reads runtime credentials.
use secure_research::config::{Capability, Config, EgressConfig};
use std::path::PathBuf;

fn main() {
    let directory = PathBuf::from(
        std::env::var_os("RESEARCH_TEST_NIXOS_CONFIG")
            .expect("set RESEARCH_TEST_NIXOS_CONFIG to the built module check output"),
    );
    let read = |name| {
        let bytes = std::fs::read(directory.join(name)).unwrap();
        assert!(bytes.len() <= 1024 * 1024);
        bytes
    };
    let service: Config = serde_json::from_slice(&read("service.json")).unwrap();
    let browser_bytes = read("browser.json");
    let browser: Config = serde_json::from_slice(&browser_bytes).unwrap();
    let summary_bytes = read("summary.json");
    let summary: Config = serde_json::from_slice(&summary_bytes).unwrap();
    let egress: EgressConfig = serde_json::from_slice(&read("egress.json")).unwrap();
    service.validate().unwrap();
    browser.validate().unwrap();
    summary.validate().unwrap();
    egress.validate().unwrap();
    let local: Config = serde_json::from_slice(&read("local-search.json")).unwrap();
    local.validate().unwrap();
    assert_eq!(local.search_order, ["searxng"]);
    assert_eq!(
        local.searxng_socket.as_deref(),
        Some(std::path::Path::new("/run/agent-research-searxng/socket"))
    );
    assert!(local.providers["searxng"].endpoint.is_none());
    assert!(local.providers["searxng"].credential.is_none());
    assert!(local.provider_allowed("searxng", Capability::Search));
    // Summarization is separately enabled: absent by default, and when granted
    // it is the only capability of its provider with a named credential/model.
    assert!(service.summarize_order.is_empty());
    assert!(!service.provider_allowed("openai", Capability::Summarize));
    assert_eq!(summary.summarize_order, vec!["openai".to_string()]);
    assert!(summary.provider_allowed("openai", Capability::Summarize));
    assert!(!summary.provider_allowed("openai", Capability::Search));
    assert_eq!(
        summary.providers["openai"].credential.as_deref(),
        Some("provider-openai")
    );
    assert_eq!(
        summary.providers["openai"].model.as_deref(),
        Some("gpt-4o-mini")
    );
    assert!(
        !String::from_utf8(summary_bytes)
            .unwrap()
            .contains("/run/secrets/")
    );
    assert_eq!(service.allowed_client_uids, vec![4100]);
    assert_eq!(service.egress_uid, Some(0));
    assert_eq!(egress.allowed_peer_uids, vec![4201]);
    assert_eq!(service.egress_socket, egress.socket_path);
    assert_eq!(service.egress_control_file, egress.control_file);
    assert_eq!(service.limits.active_jobs, 4);
    assert_eq!(service.retention.days, 7);
    assert!(!service.browser.enable);
    assert!(!service.provider_allowed("brave", Capability::Search));
    assert!(browser.browser.enable);
    assert!(browser.provider_allowed("brave", Capability::Search));
    assert_eq!(
        browser.providers["brave"].credential.as_deref(),
        Some("provider-brave")
    );
    assert!(
        !String::from_utf8(browser_bytes)
            .unwrap()
            .contains("/run/secrets/")
    );
    println!("NixOS-generated service/browser/egress configurations pass production schemas");
}
