# Log Sanitizer

A browser-local interface for [SOC Prime LogTotal Sanitizer](https://github.com/socprime/logtotal-sanitizer). Upload one UTF-8 log file or paste incident notes, select built-in redaction rules, inspect a bounded preview, and export the result. For inputs up to 50 MiB, an opt-in recovery table can display original and redacted values and export them as Markdown, CSV, or JSON.

## Privacy

Input, output, replacement values, and reports remain in the browser. The app has no backend, telemetry, analytics, runtime CDN imports, or application-initiated network requests. A random HMAC key is stored only in the current tab's `sessionStorage` so replacements remain consistent through refreshes; Clear session replaces it.

Recovery tables contain the sensitive values removed from the sanitized output. They are disabled by default and should be stored separately from sanitized logs.

The browser still requests the static application files from GitHub Pages when the page loads. Following the source-library link navigates away only after a user click.

The app never automatically selects or overwrites the source. It recommends a distinct output name; you control the native destination.

## Browser limits

| Browser capability | Limit |
| --- | ---: |
| Direct-to-disk streaming | 250 MiB per file |
| In-memory file fallback | 50 MiB per file |
| Pasted UTF-8 text | 50 MiB |

The app detects capabilities rather than browser names. Only strict UTF-8, with an optional UTF-8 BOM, is supported.

## Local development

Requires Bun 1.4.0.

```bash
bun ci
bun run test
bun run dev
bun run build
```

The Content Security Policy blocks Vite's hot-reload WebSocket. Refresh manually during local development.

## Disclaimer

This tool is provided “as is,” without warranty of any kind. Sanitization may be incomplete or inaccurate. You are responsible for reviewing the output and confirming that all sensitive information has been removed before sharing or distributing it.

## License and attribution

This project is licensed under the [MIT License](LICENSE).

It uses `@socprime/logtotal-sanitizer` under the Apache-2.0 license. See the bundled [third-party license terms](public/THIRD_PARTY_LICENSES.txt) and the [upstream repository](https://github.com/socprime/logtotal-sanitizer).
