# Security policy and threat model

Report suspected vulnerabilities privately through GitHub's security advisory
reporting for this repository. Do not post credentials or sensitive source bodies
in public issues. No version currently has a production security-support guarantee.

The intended deployment uses a trusted NixOS host and kernel, dedicated non-root
service/egress identities, an operator-managed VPN and isolated client sessions.
Host root, the Nix daemon and deployment configuration are trusted. A hostile
kernel or privileged host administrator is outside the boundary.

The untrusted inputs are agent requests, public DNS answers, provider responses,
HTML, PDF and JavaScript. They must not grant additional network, filesystem,
provider or execution authority. The research client is not a general proxy.

- The adapter uses only Unix sockets; client authorization and job ownership use
  `SO_PEERCRED`. Each container relay has its own host UID. Containers with the
  same internal UID must never share an upstream client identity.
  Reconnected sessions repeat the protocol handshake and peer authorization;
  they never replay dispatched operations or reopen an explicitly closed client.
- The supervisor, browser and parsers have independent private network namespaces.
  Only egress may contact public HTTP/HTTPS destinations through the configured VPN.
  Mixed public/private DNS answers, restricted addresses, unsafe ports and redirect
  targets are rejected. Workers do not receive provider credentials.
- Firewall rules recheck output and postrouting without an established-connection
  bypass. A trusted VPN's marked outer UDP exception is limited to declared peers.
  Unprivileged research identities cannot set that mark.
- Jobs, IPC frames, concurrency, response sizes, deadlines, spending and archives
  are bounded. Parser/browser descendants are supervised. The NixOS slice bounds
  aggregate memory/tasks and worker scratch space.
- Provider keys are runtime systemd credentials. Logs contain bounded categorical
  metadata; source bodies, queries and keys must not enter diagnostics.

Residual risks include kernel/browser/parser vulnerabilities, incomplete evidence,
provider-side privacy and billing behavior, denial of service and indirect prompt
injection. An untrusted-content label does not prevent an agent following a page's
instructions. Review [verification](docs/verification.md) before deployment;
passing a synthetic fixture is not proof of arbitrary escape resistance.

Public addresses can still receive user-supplied URL/query information. This tool
does not implement organization-specific data-loss prevention. Operators must
review grants, clients, retention and destination policy for their deployment.

Do not expose the Unix socket through an unauthenticated TCP/HTTP listener. Do not
mount host roots, Docker sockets, private configuration or the whole Nix store
into workers. Do not disable Chromium's sandbox or permit worker IP networking
to work around a failed check.
