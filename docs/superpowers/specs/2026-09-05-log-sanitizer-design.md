# Browser-Local Log Sanitizer Design

**Date:** 2026-09-05
**Status:** Approved

## Purpose

Build a public GitHub Pages tool that lets an analyst sanitize one UTF-8 log
file or one block of incident notes at a time. Sanitization happens entirely in
the browser with `@socprime/logtotal-sanitizer`. Uploaded and pasted content,
sanitized output, reports, and replacement values are never sent over the
network.

## Goals

- Accept one uploaded file or one pasted-text input at a time.
- Expose every built-in sanitizer rule as an on-by-default checkbox.
- Expose aggressive detection as an off-by-default toggle.
- Keep the page responsive while sanitizing.
- Preserve stable replacement tokens across all runs in one tab, including
  page refreshes.
- Show match counts and a bounded before/after preview.
- Copy pasted results and download pasted or file results.
- Support files up to 250 MiB without holding the full output in memory when
  the browser provides direct-to-disk streaming.
- Support current stable Chrome, Edge, Firefox, and Safari on desktop, with a
  conservative limit for browsers that cannot stream output directly to disk.
- Make the browser-local privacy claim visible and technically enforceable.

## Non-goals

- A backend, API, account system, or authentication.
- Multiple simultaneous inputs, batches, folders, or session history.
- Editing the complete sanitized result in the app.
- Custom regular expressions, custom rules, allowlists, or forced-redaction
  lists.
- Persistent preferences or keys beyond the lifetime of one browser tab.
- A service worker, PWA installation, offline mode, telemetry, analytics,
  remote fonts, or runtime CDN assets.
- Automatic legacy text-encoding detection.
- Mobile-browser support guarantees.

## Technical approach

Use a small Vite application written in vanilla TypeScript, HTML, and CSS. The
only runtime library is an exactly pinned version of
`@socprime/logtotal-sanitizer`; its lockfile is committed. The app uses one Web
Worker for decoding and sanitization. There is no UI framework, design system,
state library, service worker, or application server.

The built site contains all scripts, styles, and assets and is deployed to
GitHub Pages. Vite emits relative asset URLs (`base: './'`) so the build works
at a project Pages URL without knowing the repository name. A strict Content
Security Policy permits only bundled same-origin resources and blocks
connections and external content. The application makes no `fetch`,
`XMLHttpRequest`, beacon, WebSocket, or analytics calls.

The sanitizer package is currently pre-1.0. Its exact version must not float.
Representative integration tests protect the app against accidental behavior
changes during deliberate dependency upgrades.

## Browser capability tiers

| Capability | Maximum input | Output path |
| --- | ---: | --- |
| Direct-to-disk streaming is available and passes the runtime capability probe | 250 MiB | User chooses a destination before processing; sanitized bytes stream to that destination |
| Direct-to-disk streaming is unavailable | 50 MiB | Sanitized output is accumulated in memory and downloaded through a Blob URL |
| Pasted text | 50 MiB of UTF-8 text | Result remains in memory for Copy or Download |

The app detects capabilities, not browser names. It communicates the active
limit beside the input control and rejects oversized input before creating a
worker or reading the complete input. The app suggests a distinct sanitized
filename and never chooses the source as the destination automatically. The
native Save dialog remains user-controlled and supplies any overwrite warning;
browser file inputs do not expose enough path information for the app to prove
that a manually chosen destination differs from the source.

The 250 MiB tier is an acceptance target rather than an assumption. Manual
acceptance testing must demonstrate it in current stable Chrome and Edge. A
high-cardinality synthetic file is included to verify that disabling raw
replacement collection and bounding the preview keep report memory stable
while output is streamed.
If 250 MiB does not pass the acceptance check, the published limit must be
lowered to the largest verified safe size rather than shipping an unsupported
claim.

## Session key lifecycle

On load, the app reads the sanitizer HMAC key from `sessionStorage`. If none is
present, it uses the library's `generateKey()` and stores the resulting key.
The same key is supplied to every sanitizer created in that tab, so the same
value and rule produce the same replacement across runs and refreshes.

Closing the tab allows the browser to remove the key. The app does not use
`localStorage`, IndexedDB, cookies, or remote persistence. A **Clear session**
action removes the current input and result, deletes the stored key, generates
a new key, and resets the interface. Browser garbage collection means the app
must not promise cryptographic erasure of previously allocated memory.

## Rules

The UI lists the library's built-in rules in its documented priority order:

1. Secrets
2. Session cookies
3. Payment information
4. Government identifiers
5. Health information
6. Phone numbers
7. IP and MAC addresses
8. Hosts
9. Users and email addresses
10. Geographic locations
11. User segments in filesystem paths

All are selected initially. Analysts may toggle individual categories. At
least one rule must remain selected before a run can start. Aggressive mode is
separate, defaults off, and includes a warning that broader matching may
redact benign values. Selected rules are always passed in the library's fixed
priority order rather than visual click order.

## User interface

Use the approved **Focused flow** layout: a full-width, single-column sequence
that preserves horizontal room for long log lines.

1. **Add content.** A file drop/select target and a pasted-text area are
   mutually exclusive. Choosing one clears the other after confirmation when
   unsaved sanitized output exists.
2. **Choose rules.** A compact checkbox grid includes short plain-language
   descriptions and the aggressive-mode toggle.
3. **Sanitize locally.** The primary action starts the worker. During a run,
   the page shows phase, bytes processed, percentage when measurable, and a
   Cancel action.
4. **Review and export.** Category counts and total matches precede a bounded
   before/after preview. File input offers Download. Pasted input offers Copy
   and Download.

The header displays **Processed entirely in this browser** with an explanation
that only the session key is kept through refresh and that no input-dependent
request is made. Attribution and a link to the Apache-2.0-licensed sanitizer
library appear in the footer.

The preview uses at most the library's first 256 KiB preview and renders no
more than 200 logical lines per side. When content is omitted, the UI says so.
Preview text is rendered as text, never interpreted as HTML. The main thread
does not receive or retain the report's raw replacement inventory.

On narrow windows, before and after previews stack. On wide windows they appear
side by side. All controls have programmatic labels and visible focus styles;
all actions are keyboard accessible. An ARIA live region announces errors,
progress milestones, cancellation, and completion. Focus moves to the first
blocking error or the result heading when appropriate. Motion is not required
to understand any state.

## Processing flow

1. Restore or generate the tab-scoped HMAC key.
2. Accept a file or pasted text and clear the other input mode.
3. Determine the browser capability tier and validate size before reading the
   complete input.
4. Inspect and decode the input as strict UTF-8, accepting an optional UTF-8
   BOM. Reject malformed UTF-8 and likely binary content with a clear message.
   Filenames and extensions do not determine validity.
5. For direct-to-disk output, request the destination from the user's click
   before starting the worker. Suggest `<stem>.sanitized.<extension>`, or
   `<name>.sanitized` when the source has no extension, and tell the user to
   keep the distinct output name.
6. Send the key, ordered selected rules, aggressive flag, input, and output
   capability to the worker.
7. The worker constructs one sanitizer and processes the input as a stream.
   Progress messages contain only byte counts and state, never source text.
8. The worker writes sanitized chunks directly to the chosen destination or,
   for the capped fallback, builds the result Blob. Pasted text is returned as
   an in-memory result.
9. The sanitizer is configured with `report.replacements: false` and zero
   context, so it never collects raw replacement inventories. The worker posts
   only line count, total matches, counts by rule, and the bounded preview to
   the main thread.
10. The UI presents the summary and export actions. Loading a new input replaces
    the previous result; the session key remains unchanged.

Worker messages are a small closed set: start, progress, complete, cancel,
cancelled, and error. No generalized job framework or reusable abstraction is
introduced.

## Cancellation and errors

Validation failures occur before processing and preserve the selected input.
They cover missing input, no selected rules, oversized input, malformed UTF-8,
likely binary data, and unavailable required browser capabilities.

Cancel asks the active worker to abort its output write. After the worker
acknowledges cancellation, or after a short failure timeout, the main thread
terminates it. Direct-to-disk writes are aborted rather than closed so
incomplete data is not committed as a successful result. Blob buffers and
preview/report references are discarded. A fresh worker is created for the
next run.

Sanitizer, decoding, storage, clipboard, and disk errors produce concise,
actionable local messages. Errors are not reported remotely. A failed run
keeps the original input available for retry but removes incomplete output and
never chooses the source file as its output automatically.

If `sessionStorage` is unavailable, the tool remains usable with an in-memory
key and clearly states that a refresh will change replacement tokens. If direct
streaming fails its runtime probe, the app falls back before processing when
the input fits the 50 MiB tier; otherwise it rejects the run and explains the
safe fallback limit.

## Privacy controls

The deployed document uses a restrictive policy equivalent to:

- `default-src 'self'`
- `connect-src 'none'`
- `object-src 'none'`
- `base-uri 'none'`
- `form-action 'none'`
- scripts, styles, images, and workers limited to the minimum bundled
  same-origin sources needed by the build

GitHub Pages limitations may require delivering the policy through a document
meta element, so unsupported response-header-only directives are not claimed.
The production bundle contains no runtime third-party URLs. Clipboard writes
occur only after an explicit user action.

## Testing and acceptance

Automated checks remain intentionally small:

- One focused Vitest file covers strict UTF-8 validation, capability-dependent
  size limits, output filename generation, selected-rule ordering, stable
  tokens with a reused key, changed tokens with a new key, and representative
  sanitizer output.
- TypeScript type-checking succeeds.
- The production Vite build succeeds with relative asset URLs suitable for a
  GitHub Pages project path.

A short manual acceptance checklist covers behavior that would require costly
browser-test scaffolding:

- Current stable Chrome and Edge sanitize a normal and a high-cardinality
  synthetic 250 MiB UTF-8 log through the direct-to-disk path without the UI
  becoming unresponsive or the tab crashing.
- Current stable Firefox and Safari reject files over 50 MiB before reading
  them and successfully sanitize a smaller file through the Blob path.
- File selection, drag-and-drop, paste, Copy, Download, cancellation, refresh
  key persistence, and Clear session work as specified.
- Keyboard-only navigation, visible focus, live announcements, and responsive
  preview layout work.
- Browser developer tools show no input-dependent or application-initiated
  network request during input, processing, preview, copy, or download.

Worker mocks, Playwright, visual snapshots, automated CSP scanning, and a large
cross-browser CI matrix are deferred until an observed regression justifies
their maintenance cost.

## Deployment

A GitHub Actions workflow builds the pinned project and deploys only the Vite
output directory to GitHub Pages. The workflow contains no input data because
all user content exists only at runtime in an analyst's browser. Deployment
documentation explains the relative-asset build and the Pages configuration
required for the public site.

## Success criteria

The tool is successful when an analyst can open the public GitHub Pages URL,
sanitize one supported file or pasted note using chosen built-in rules, verify
the bounded result summary, and export it without any source or output content
leaving the browser. It remains responsive at the stated capability-tier
limits, produces stable tokens throughout one tab session, and fails without
committing incomplete sanitized content.
