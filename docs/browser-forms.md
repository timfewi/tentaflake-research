# Guided browser forms: design proposal

Status: design only. This adds a write-like browser capability beyond R01–R27
and needs an owner decision before implementation. It must remain separate from
the six read actions and from the existing reviewed raw-POST rules.

## Capability boundary

The operator defines immutable recipes in service configuration. A request can
select a recipe and supply values only for named fields declared by that recipe.
Page content and tool input cannot add fields, change the target, select a
credential, choose an HTTP method or weaken confirmation. Filling and submission
are distinct actions; filling never authorizes submission.

Each recipe pins the expected origin, action path, method, encoding, bounded
field schema and a hash of the structural form description observed during
review. Redirects and every resulting request still pass the browser request
gate. Password, file, image, payment, login and CAPTCHA controls are excluded.
Cross-origin actions, custom schemes, `_blank`, `formaction`, arbitrary headers
and page-provided authorization are rejected.

Hidden controls are split into two classes. Operator constants are pinned in the
recipe. Page-carried freshness values such as CSRF tokens may be submitted only
when the recipe explicitly declares their names, source form and size; their
values stay inside the worker and are never returned to the model or logs.
Unexpected successful controls fail closed. `_charset_`, `dirname`, image
coordinates and file inputs are unsupported.

## HTML semantics and execution

The worker resolves an empty action against the current document URL and applies
the document base URL exactly once before policy validation. It implements the
successful-control rules for the supported input types, including checked state,
disabled fieldsets, selected options and the chosen submitter. Constraint
validation is useful feedback, but never a security check.

The worker uses native input events for user-like editing and reads every value
back from the target control. A mismatch fails before submission. Submission
uses the reviewed submitter so page `submit` handlers and browser validation run;
`form.submit()` is forbidden because it bypasses both. Immediately before the
request is released, the service rechecks the recipe, serialized body digest,
origin/path, content type and byte budget. This is the final authorization point.

Submission requires a separate executor-side confirmation bound to job, session,
page version, recipe ID, target origin, field-name set and body digest. The tool
response may show field names and redacted value classes, never hidden-token or
password-like values. A recipe must declare whether one replay is safe; the
default is no automatic retry after an uncertain outcome.

## Proposed configuration and protocol

`browser.formRecipes.<id>` contains `origin`, `path`, `method`, `encoding`,
`formFingerprint`, `fields`, `carriedFields`, `maxBodyBytes`, redirect policy and
optional idempotency evidence. The MCP surface should add explicit `form_inspect`,
`form_fill` and `form_submit` actions only after a protocol-version decision.
References remain bound to document, URL, page version and control fingerprint.

## Required evidence

- Unit fixtures for successful-control serialization, encodings, `<base>`, empty
  actions, disabled controls, duplicate names and submitter overrides.
- Malicious DOM fixtures for post-review mutation, clobbering, shadow DOM,
  nested frames, getters/listeners, unexpected hidden controls and token leakage.
- Real Chromium tests proving read-back failure, validation behavior, exact body
  and preflight handling, stale references, confirmation binding and no replay.
- Service tests proving a worker cannot select recipes or expose carried values,
  and that cancellation preserves uncertain side-effect accounting.
- Deployment tests retaining the current filesystem, network, credential and
  descendant-cleanup boundaries.

Open decisions: confirmation UX and authority, supported encodings/input types,
whether same-origin frames are ever allowed, recipe review tooling, and how
operators rotate recipes when a site legitimately changes its form.
