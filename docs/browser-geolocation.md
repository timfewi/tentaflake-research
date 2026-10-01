# Browser geolocation: design proposal

Status: deferred capability design. Locale/timezone/Accept-Language currently
adapt coherently between sessions. Geolocation is different because Chromium
requires both emulation data and a permission decision visible to the page.

## Capability boundary

Geolocation is disabled by default and cannot be selected by tool input. An
operator may enable one coarse location profile associated with a trusted exit
region. Latitude, longitude and accuracy must form a coherent tuple with locale,
timezone and observed exit region. The profile is chosen once before a session
and never changes mid-session. Unknown regions yield no geolocation capability.

Permission is granted only to exact operator-configured HTTPS origins. Redirects,
subframes and newly opened targets do not inherit it. The permission list is
separate from search country hints and browser network grants. No prompt clicking
or page-requested escalation is allowed. Coordinates are configuration data and
must not be returned in ordinary page metadata or diagnostics.

## CDP application

After target ownership is established and before navigation, apply a bounded
`Emulation.setGeolocationOverride` and an origin-scoped browser permission. The
implementation must confirm the pinned Chromium/CDP API shape before coding.
Clearing the override and resetting permissions are mandatory during teardown,
even though the profile is ephemeral. New child sessions default to no grant.

Exact GPS-like coordinates create unnecessary fingerprinting and privacy risk.
Use coarse, documented centroids with conservative accuracy, or omit the feature.
The service makes no claim that coordinates prove or hide physical location.

## Required evidence

- Validation tests for finite/ranged coordinates, accuracy bounds, exact HTTPS
  origins and coherent region/profile selection.
- Real Chromium fixtures for allowed top-level access, denied other origin,
  denied iframe/popup/worker, no prompt interaction and teardown reset.
- Observed consistency among geolocation, timezone, locale, language headers,
  user agent/client hints and the trusted exit-region lease.
- Rotation tests proving existing sessions retain their original profile while a
  new session adopts a new lease generation.
- Privacy review covering configuration exposure, evidence retention and logs.

Open decisions: whether the research use case justifies revealing location at
all, allowed origins, coordinate granularity, accuracy range and behavior when a
site requires geolocation before content becomes readable.
