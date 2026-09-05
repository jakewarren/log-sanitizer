# Log Sanitizer

A browser-local interface for [SOC Prime LogTotal Sanitizer](https://github.com/socprime/logtotal-sanitizer). Upload one UTF-8 log file or paste incident notes, select built-in redaction rules, inspect a bounded preview, and export the result.

## Privacy

Input, output, replacement values, and reports remain in the browser. The app has no backend, telemetry, analytics, runtime CDN imports, or application-initiated network requests. A random HMAC key is stored only in the current tab's `sessionStorage` so replacements remain consistent through refreshes; Clear session replaces it.

The browser still requests the static application files from GitHub Pages when the page loads. Following the source-library link navigates away only after a user click.

Source files are never modified; sanitized output is written to a newly chosen destination or downloaded by the browser.

## Browser limits

| Browser capability | Limit |
| --- | ---: |
| Direct-to-disk streaming | 250 MiB per file |
| In-memory file fallback | 50 MiB per file |
| Pasted UTF-8 text | 50 MiB |

The app detects capabilities rather than browser names. Only strict UTF-8, with an optional UTF-8 BOM, is supported.

## Local development

Requires Bun 1.4.0 or newer.

```bash
bun ci
bun run test
bun run dev
bun run build
```

The Content Security Policy blocks Vite's hot-reload WebSocket. Refresh manually during local development.

## GitHub Pages

1. Push the `main` branch to GitHub.
2. In **Settings → Pages → Build and deployment**, select **GitHub Actions** as the source.
3. Run the **Deploy GitHub Pages** workflow or push to `main`.

The build uses relative asset URLs, so no repository-name configuration is required.

## License and attribution

This application uses `@socprime/logtotal-sanitizer` under the Apache-2.0 license. See that project's repository for its license and notices.
