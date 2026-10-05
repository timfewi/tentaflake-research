# Source provenance

The initial Rust service, NixOS boundary and synthetic tests were extracted from
the MIT-licensed `secure-research-tool` source snapshot
`b477ec4c0437e11fb4bfe72918ce065ad39600cc`.

The original copyright notice is preserved in LICENSE. Third-party dependencies
keep their own licenses and are pinned in Cargo.lock and flake.lock. No private
Git history, host configuration, credentials, runtime state or agent transcripts
were imported. Public documentation describes this repository's current scope;
historical development notes are not imported or treated as acceptance evidence.


The 2026-10-03 local follow-up selectively adapts the MIT-licensed snapshot
`fad984b65536bf3fad5d60d7039a3b1e6fc0fd7e`: the client/service Cargo separation,
static streamed-HTML and page-shell handling, and redirect-aware crawl deduplication.
The public client's recovery rules, container relay boundary and five-tool
interface remain authoritative. Contact enrichment, deployment configuration,
runtime provider catalogues and private historical documentation were not imported.

The 2026-10-05 follow-up selectively adapts the MIT-licensed snapshot
`4c2030c`: formatted HTML text (`research-html/v3`), the constrained package
source selection, typed job-limit and browser-denial failure details, and the
short RPC fixture sockets. The five-tool interface, the public client's recovery
rules and the exclusion of contact enrichment, runtime provider catalogues and
private historical documentation remain unchanged.
