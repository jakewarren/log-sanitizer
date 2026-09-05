# Browser-Local Log Sanitizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a public GitHub Pages tool that sanitizes one UTF-8 log file or pasted incident note entirely inside the browser.

**Architecture:** A vanilla TypeScript/Vite page owns the accessible UI and tab-scoped key. One Web Worker runs `@socprime/logtotal-sanitizer` against a strict UTF-8 source, writing either to a browser file handle or a capped in-memory result.

**Tech Stack:** Bun 1.4.0, TypeScript 7.0.2, Vite 8.2.2, Vitest 5.0.0, `@socprime/logtotal-sanitizer` 0.1.0-beta.0, native Web Workers, File/Blob/Clipboard/sessionStorage APIs, GitHub Pages.

**Spec:** `docs/superpowers/specs/2026-09-05-log-sanitizer-design.md`

## Global Constraints

- Use Bun for package management and scripts; keep `@socprime/logtotal-sanitizer` pinned exactly to `0.1.0-beta.0` and commit `bun.lock`.
- Keep all runtime assets in the built site: no backend, telemetry, analytics, remote fonts, CDN imports, or application-initiated network calls.
- Process one input at a time; accept strict UTF-8 with an optional UTF-8 BOM.
- Use all built-in rules by default, preserve the library's rule priority, and default aggressive mode off.
- Keep one HMAC key per tab in `sessionStorage`; replace it when Clear session is used.
- Set `report.replacements` to `false`, `report.previewBytes` to 262,144, and render at most 200 preview lines per side.
- Cap direct-to-disk file inputs at 250 MiB and all in-memory routes, including pasted text, at 50 MiB.
- Never choose or overwrite the source automatically. Suggest a distinct sanitized filename, leave the destination under user control, and abort incomplete output on cancellation or failure.
- Support current stable desktop Chrome, Edge, Firefox, and Safari through capability detection rather than user-agent checks.
- Preserve input validation, safe failure behavior, CSP, and baseline accessibility even when simplifying.

## File Structure

- `.gitignore` — ignore dependencies, build output, and visual-companion state.
- `package.json` / `bun.lock` — exact dependency versions and three scripts: dev, test, build.
- `tsconfig.json` — strict browser TypeScript configuration with no emitted type-check output.
- `vite.config.ts` — static build with relative asset URLs for any GitHub Pages project path.
- `index.html` — semantic single-screen shell and restrictive CSP.
- `src/policy.ts` — tested constants and pure helpers for limits, filenames, rules, preview bounds, binary checks, and session keys.
- `src/protocol.ts` — the closed request/response union shared by the page and worker.
- `src/sanitization.ts` — strict streaming decoder plus disk and memory sinks around the sanitizer library.
- `src/sanitize.worker.ts` — thin worker message adapter and cancellation owner.
- `src/main.ts` — DOM wiring, input preflight, worker lifecycle, result rendering, copy/download, and Clear session.
- `src/styles.css` — focused-flow responsive layout and accessible states.
- `tests/app.test.ts` — the single focused Vitest file for policy and sanitizer integration behavior.
- `.github/workflows/pages.yml` — test, build, upload, and deploy the static Pages artifact.
- `README.md` — privacy model, browser limits, local commands, and Pages setup.

---

### Task 1: Project Foundation and Browser Policy

**Files:**
- Create: `.gitignore`
- Create: `package.json`
- Create: `bun.lock` via `bun install`
- Create: `tsconfig.json`
- Create: `vite.config.ts`
- Create: `tests/app.test.ts`
- Create: `src/policy.ts`

**Interfaces:**
- Consumes: `builtinRuleIds`, `builtinRules`, `generateKey`, and `sanitizeText` from `@socprime/logtotal-sanitizer`.
- Produces: `DIRECT_LIMIT_BYTES`, `MEMORY_LIMIT_BYTES`, `PREVIEW_BYTES`, `PREVIEW_LINES`, `RULES`, `getInputLimit()`, `validateInputSize()`, `outputFileName()`, `isProbablyBinary()`, `orderRuleIds()`, `limitPreviewSegments()`, `getOrCreateSessionKey()`, and `replaceSessionKey()`.

- [ ] **Step 1: Create the minimal package and TypeScript setup**

Create `.gitignore`:

```gitignore
node_modules/
dist/
.superpowers/
.DS_Store
```

Create `package.json`:

```json
{
  "name": "log-sanitizer",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "packageManager": "bun@1.4.0",
  "engines": {
    "bun": ">=1.4.0"
  },
  "scripts": {
    "dev": "vite",
    "test": "vitest run",
    "build": "tsc --noEmit && vite build"
  },
  "dependencies": {
    "@socprime/logtotal-sanitizer": "0.1.0-beta.0"
  },
  "devDependencies": {
    "typescript": "7.0.2",
    "vite": "8.2.2",
    "vitest": "5.0.0"
  }
}
```

Create `tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "useDefineForClassFields": true,
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "noEmit": true
  },
  "include": ["src", "vite.config.ts"]
}
```

Create the initial `vite.config.ts`; Task 4 changes the base after first writing a failing deployment test:

```ts
import { defineConfig } from 'vite';

export default defineConfig({ base: '/' });
```

Run:

```bash
bun install
```

Expected: Bun creates `bun.lock` with the exact versions above.

- [ ] **Step 2: Write the failing policy tests**

Create `tests/app.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { sanitizeText } from '@socprime/logtotal-sanitizer';
import {
  DIRECT_LIMIT_BYTES,
  MEMORY_LIMIT_BYTES,
  getInputLimit,
  getOrCreateSessionKey,
  isProbablyBinary,
  limitPreviewSegments,
  orderRuleIds,
  outputFileName,
  replaceSessionKey,
  validateInputSize,
} from '../src/policy';

function memoryStorage() {
  const values = new Map<string, string>();
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
    removeItem: (key: string) => void values.delete(key),
  };
}

describe('browser policy', () => {
  it('uses capability-dependent limits', () => {
    expect(getInputLimit('file', true)).toBe(DIRECT_LIMIT_BYTES);
    expect(getInputLimit('file', false)).toBe(MEMORY_LIMIT_BYTES);
    expect(getInputLimit('text', true)).toBe(MEMORY_LIMIT_BYTES);
    expect(validateInputSize(MEMORY_LIMIT_BYTES + 1, 'file', false)).toMatch(/50 MiB/);
    expect(validateInputSize(MEMORY_LIMIT_BYTES, 'file', false)).toBeNull();
  });

  it('inserts the sanitized marker before a normal extension', () => {
    expect(outputFileName('app.log')).toBe('app.sanitized.log');
    expect(outputFileName('README')).toBe('README.sanitized');
    expect(outputFileName('.env')).toBe('.env.sanitized');
  });

  it('rejects likely binary samples without rejecting normal controls', () => {
    expect(isProbablyBinary(new Uint8Array([0x61, 0x00, 0x62]))).toBe(true);
    expect(isProbablyBinary(new TextEncoder().encode('one\ttwo\nthree\r\n'))).toBe(false);
  });

  it('orders selected rules by the library registry', () => {
    expect(orderRuleIds(['users', 'secrets', 'not-a-rule'])).toEqual(['secrets', 'users']);
  });

  it('limits preview segments without losing changed flags', () => {
    const result = limitPreviewSegments(
      [{ text: 'one\ntwo\n', changed: false }, { text: 'three', changed: true }],
      2,
    );
    expect(result.truncated).toBe(true);
    expect(result.segments).toEqual([{ text: 'one\ntwo', changed: false }]);
  });

  it('reuses and replaces a tab-scoped key', () => {
    const storage = memoryStorage();
    const first = getOrCreateSessionKey(storage);
    expect(getOrCreateSessionKey(storage).key).toBe(first.key);
    const replacement = replaceSessionKey(storage);
    expect(replacement.key).not.toBe(first.key);
    expect(getOrCreateSessionKey(storage).key).toBe(replacement.key);
  });

  it('produces stable tokens for one key and different tokens for a new key', () => {
    const input = 'connection from 10.0.0.7';
    const keyA = '11'.repeat(32);
    const keyB = '22'.repeat(32);
    const options = { rules: ['ips'] as const, keyEncoding: 'hex' as const };
    const first = sanitizeText(input, { ...options, key: keyA }).output;
    expect(sanitizeText(input, { ...options, key: keyA }).output).toBe(first);
    expect(sanitizeText(input, { ...options, key: keyB }).output).not.toBe(first);
  });
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run:

```bash
bun run test
```

Expected: FAIL because `src/policy.ts` does not exist.

- [ ] **Step 4: Implement the browser policy helpers**

Create `src/policy.ts`:

```ts
import {
  builtinRuleIds,
  builtinRules,
  generateKey,
  type BuiltinRuleId,
  type SanitizeSegment,
} from '@socprime/logtotal-sanitizer';

export const DIRECT_LIMIT_BYTES = 250 * 1024 * 1024;
export const MEMORY_LIMIT_BYTES = 50 * 1024 * 1024;
export const PREVIEW_BYTES = 256 * 1024;
export const PREVIEW_LINES = 200;
export const SESSION_KEY = 'log-sanitizer:hmac-key';

export const RULES = builtinRules.map(({ id, label, description }) => ({
  id: id as BuiltinRuleId,
  label,
  description,
}));

export type InputKind = 'file' | 'text';
export type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

export interface SessionKeyState {
  key: string;
  persisted: boolean;
}

export function getInputLimit(kind: InputKind, canStreamToDisk: boolean): number {
  return kind === 'file' && canStreamToDisk ? DIRECT_LIMIT_BYTES : MEMORY_LIMIT_BYTES;
}

export function validateInputSize(
  size: number,
  kind: InputKind,
  canStreamToDisk: boolean,
): string | null {
  const limit = getInputLimit(kind, canStreamToDisk);
  if (size <= limit) return null;
  const label = limit === DIRECT_LIMIT_BYTES ? '250 MiB' : '50 MiB';
  return `This input is larger than the ${label} limit for the available output method.`;
}

export function outputFileName(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot > 0
    ? `${name.slice(0, dot)}.sanitized${name.slice(dot)}`
    : `${name}.sanitized`;
}

export function isProbablyBinary(sample: Uint8Array): boolean {
  if (sample.length === 0) return false;
  let suspicious = 0;
  for (const byte of sample) {
    if (byte === 0) return true;
    if (byte < 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0c && byte !== 0x0d) {
      suspicious += 1;
    }
  }
  return suspicious / sample.length > 0.1;
}

export function orderRuleIds(selected: readonly string[]): BuiltinRuleId[] {
  const wanted = new Set(selected);
  return builtinRuleIds.filter((id) => wanted.has(id));
}

export function limitPreviewSegments(
  segments: readonly SanitizeSegment[],
  maxLines = PREVIEW_LINES,
): { segments: SanitizeSegment[]; truncated: boolean } {
  const limited: SanitizeSegment[] = [];
  let lines = 1;

  for (const segment of segments) {
    for (let index = 0; index < segment.text.length; index += 1) {
      if (segment.text[index] !== '\n') continue;
      if (lines === maxLines) {
        const text = segment.text.slice(0, index);
        if (text) limited.push({ text, changed: segment.changed });
        return { segments: limited, truncated: true };
      }
      lines += 1;
    }
    limited.push({ ...segment });
  }

  return { segments: limited, truncated: false };
}

export function getOrCreateSessionKey(storage?: StorageLike): SessionKeyState {
  try {
    const existing = storage?.getItem(SESSION_KEY);
    if (existing && /^[0-9a-f]{64}$/.test(existing)) {
      return { key: existing, persisted: true };
    }
    const key = generateKey();
    storage?.setItem(SESSION_KEY, key);
    return { key, persisted: storage !== undefined };
  } catch {
    return { key: generateKey(), persisted: false };
  }
}

export function replaceSessionKey(storage?: StorageLike): SessionKeyState {
  const key = generateKey();
  try {
    storage?.removeItem(SESSION_KEY);
    storage?.setItem(SESSION_KEY, key);
    return { key, persisted: storage !== undefined };
  } catch {
    return { key, persisted: false };
  }
}
```

- [ ] **Step 5: Run the checks**

Run:

```bash
bun run test
bunx tsc --noEmit
```

Expected: tests PASS and TypeScript reports no errors. The production build begins in Task 3 after the page entry exists.

- [ ] **Step 6: Commit Task 1**

```bash
git add .gitignore package.json bun.lock tsconfig.json vite.config.ts src/policy.ts tests/app.test.ts
git commit -m "chore: bootstrap browser sanitizer"
```

---

### Task 2: Streaming Sanitizer and Worker Boundary

**Files:**
- Create: `src/protocol.ts`
- Create: `src/sanitization.ts`
- Create: `src/sanitize.worker.ts`
- Modify: `tests/app.test.ts`

**Interfaces:**
- Consumes: Task 1's `PREVIEW_BYTES` and ordered `BuiltinRuleId[]` values.
- Produces: `StartMessage`, `WorkerRequest`, `WorkerResponse`, `CompleteResult`, `WritableFileHandleLike`, `strictUtf8Source()`, and `runSanitization()` for Task 3.

- [ ] **Step 1: Append failing streaming tests to the single test file**

Add these imports to `tests/app.test.ts`:

```ts
import { strictUtf8Source, runSanitization } from '../src/sanitization';
import type { StartMessage, WritableFileHandleLike } from '../src/protocol';
```

Append:

```ts
async function collect(source: AsyncIterable<string>): Promise<string> {
  let value = '';
  for await (const chunk of source) value += chunk;
  return value;
}

describe('streaming sanitizer', () => {
  it('decodes a BOM and split multi-byte UTF-8 sequence', async () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, 0x41, 0xe2, 0x82, 0xac, 0x42]);
    expect(await collect(strictUtf8Source(new Blob([bytes]), () => undefined, 2))).toBe('A€B');
  });

  it('rejects malformed UTF-8', async () => {
    const malformed = new Blob([new Uint8Array([0xc3, 0x28])]);
    await expect(collect(strictUtf8Source(malformed, () => undefined, 1))).rejects.toThrow(
      'Input is not valid UTF-8',
    );
  });

  it('returns a bounded in-memory text result without raw replacements', async () => {
    const request: StartMessage = {
      type: 'start',
      key: '11'.repeat(32),
      rules: ['ips'],
      aggressive: false,
      input: { kind: 'text', text: 'from 10.0.0.7', outputName: 'sanitized.txt' },
      destination: { kind: 'memory' },
    };
    const result = await runSanitization(request, new AbortController().signal, () => undefined);
    expect(result.kind).toBe('text');
    if (result.kind !== 'text') throw new Error('Expected text result');
    expect(result.text).toMatch(/<IP:[0-9a-f]{16}>/);
    expect(result.report.totalMatches).toBe(1);
    expect('replacements' in result.report).toBe(false);
  });

  it('streams to a file-like handle and closes only on success', async () => {
    const chunks: string[] = [];
    let closed = false;
    let aborted = false;
    const handle: WritableFileHandleLike = {
      async createWritable() {
        return {
          async write(chunk) {
            chunks.push(chunk);
          },
          async close() {
            closed = true;
          },
          async abort() {
            aborted = true;
          },
        };
      },
    };
    const request: StartMessage = {
      type: 'start',
      key: '11'.repeat(32),
      rules: ['ips'],
      aggressive: false,
      input: { kind: 'file', blob: new Blob(['from 10.0.0.7']), outputName: 'app.sanitized.log' },
      destination: { kind: 'disk', handle },
    };
    const result = await runSanitization(request, new AbortController().signal, () => undefined);
    expect(result.kind).toBe('disk');
    expect(chunks.join('')).toMatch(/<IP:[0-9a-f]{16}>/);
    expect(closed).toBe(true);
    expect(aborted).toBe(false);
  });

  it('honors cancellation before writing', async () => {
    const controller = new AbortController();
    controller.abort();
    const request: StartMessage = {
      type: 'start',
      key: '11'.repeat(32),
      rules: ['ips'],
      aggressive: false,
      input: { kind: 'text', text: 'from 10.0.0.7', outputName: 'sanitized.txt' },
      destination: { kind: 'memory' },
    };
    await expect(runSanitization(request, controller.signal, () => undefined)).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run:

```bash
bun run test
```

Expected: FAIL because `src/sanitization.ts` and `src/protocol.ts` do not exist.

- [ ] **Step 3: Define the closed worker protocol**

Create `src/protocol.ts`:

```ts
import type {
  BuiltinRuleId,
  RuleCounts,
  SanitizeSegment,
} from '@socprime/logtotal-sanitizer';

export interface WritableFileLike {
  write(data: string): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}

export interface WritableFileHandleLike {
  createWritable(): Promise<WritableFileLike>;
}

export type SanitizerInput =
  | { kind: 'file'; blob: Blob; outputName: string }
  | { kind: 'text'; text: string; outputName: string };

export type OutputDestination =
  | { kind: 'disk'; handle: WritableFileHandleLike }
  | { kind: 'memory' };

export interface StartMessage {
  type: 'start';
  key: string;
  rules: BuiltinRuleId[];
  aggressive: boolean;
  input: SanitizerInput;
  destination: OutputDestination;
}

export interface CancelMessage {
  type: 'cancel';
}

export interface ReportSummary {
  counts: RuleCounts;
  totalMatches: number;
  lineCount: number;
  preview: { before: SanitizeSegment[]; after: SanitizeSegment[] };
}

export type CompleteResult =
  | { kind: 'disk'; report: ReportSummary }
  | { kind: 'blob'; blob: Blob; fileName: string; report: ReportSummary }
  | { kind: 'text'; text: string; fileName: string; report: ReportSummary };

export type WorkerRequest = StartMessage | CancelMessage;

export type WorkerResponse =
  | { type: 'progress'; bytesRead: number; totalBytes: number }
  | { type: 'complete'; result: CompleteResult }
  | { type: 'cancelled' }
  | {
      type: 'error';
      code: 'invalid-utf8' | 'disk-unavailable' | 'quota' | 'failed';
      message: string;
    };
```

- [ ] **Step 4: Implement strict streaming and both output sinks**

Create `src/sanitization.ts`:

```ts
import {
  createSanitizer,
  type SanitizeReport,
  type TextSink,
} from '@socprime/logtotal-sanitizer';
import { PREVIEW_BYTES } from './policy';
import type {
  CompleteResult,
  ReportSummary,
  StartMessage,
  WritableFileLike,
} from './protocol';

const CHUNK_BYTES = 4 * 1024 * 1024;
const MEMORY_PART_CHARS = 1024 * 1024;

export class InvalidUtf8Error extends Error {
  constructor() {
    super('Input is not valid UTF-8. Convert it to UTF-8 and try again.');
  }
}

export async function* strictUtf8Source(
  blob: Blob,
  onBytesRead: (bytesRead: number) => void,
  chunkBytes = CHUNK_BYTES,
): AsyncGenerator<string> {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  try {
    for (let offset = 0; offset < blob.size; offset += chunkBytes) {
      const end = Math.min(offset + chunkBytes, blob.size);
      const bytes = new Uint8Array(await blob.slice(offset, end).arrayBuffer());
      const text = decoder.decode(bytes, { stream: true });
      onBytesRead(end);
      if (text) yield text;
    }
    const tail = decoder.decode();
    if (tail) yield tail;
  } catch (error) {
    if (error instanceof TypeError) throw new InvalidUtf8Error();
    throw error;
  }
}

function memorySink() {
  const parts: string[] = [];
  let pending: string[] = [];
  let pendingChars = 0;

  function flush(): void {
    if (pending.length === 0) return;
    parts.push(pending.join(''));
    pending = [];
    pendingChars = 0;
  }

  const sink: TextSink = {
    write(chunk) {
      pending.push(chunk);
      pendingChars += chunk.length;
      if (pendingChars >= MEMORY_PART_CHARS) flush();
    },
    close: flush,
  };

  return {
    sink,
    text(): string {
      flush();
      return parts.join('');
    },
    blob(): Blob {
      flush();
      return new Blob(parts, { type: 'text/plain;charset=utf-8' });
    },
  };
}

function summarize(report: SanitizeReport): ReportSummary {
  return {
    counts: report.counts,
    totalMatches: report.totalMatches,
    lineCount: report.lineCount,
    preview: report.preview,
  };
}

export async function runSanitization(
  message: StartMessage,
  signal: AbortSignal,
  onProgress: (bytesRead: number, totalBytes: number) => void,
): Promise<CompleteResult> {
  const blob = message.input.kind === 'file'
    ? message.input.blob
    : new Blob([message.input.text], { type: 'text/plain;charset=utf-8' });
  let bytesRead = 0;
  const source = strictUtf8Source(blob, (value) => {
    bytesRead = value;
  });
  const sanitizer = createSanitizer({
    key: message.key,
    keyEncoding: 'hex',
    rules: message.rules,
    aggressive: message.aggressive,
    report: { previewBytes: PREVIEW_BYTES, replacements: false, contextChars: 0 },
  });

  let writable: WritableFileLike | undefined;
  const memory = message.destination.kind === 'memory' ? memorySink() : undefined;
  const sink: TextSink = message.destination.kind === 'disk'
    ? {
        async write(chunk) {
          if (!writable) throw new Error('Output file is not open.');
          await writable.write(chunk);
        },
        async close() {
          if (!writable) throw new Error('Output file is not open.');
          await writable.close();
          writable = undefined;
        },
      }
    : memory!.sink;

  try {
    if (message.destination.kind === 'disk') {
      writable = await message.destination.handle.createWritable();
    }
    const report = await sanitizer.sanitizeStream(source, sink, {
      signal,
      onProgress: () => onProgress(bytesRead, blob.size),
    });
    const summary = summarize(report);

    if (message.destination.kind === 'disk') return { kind: 'disk', report: summary };
    if (message.input.kind === 'text') {
      return {
        kind: 'text',
        text: memory!.text(),
        fileName: message.input.outputName,
        report: summary,
      };
    }
    return {
      kind: 'blob',
      blob: memory!.blob(),
      fileName: message.input.outputName,
      report: summary,
    };
  } catch (error) {
    if (writable) {
      await writable.abort(error).catch(() => undefined);
      writable = undefined;
    }
    throw error;
  }
}
```

Do not add a filesystem-access typings package for one structural type.

- [ ] **Step 5: Implement the thin worker adapter**

Create `src/sanitize.worker.ts`:

```ts
import { InvalidUtf8Error, runSanitization } from './sanitization';
import type { WorkerRequest, WorkerResponse } from './protocol';

interface WorkerScope {
  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerRequest>) => void): void;
  postMessage(message: WorkerResponse): void;
}

const scope = globalThis as unknown as WorkerScope;
let active: AbortController | undefined;

function post(message: WorkerResponse): void {
  scope.postMessage(message);
}

scope.addEventListener('message', (event) => {
  if (event.data.type === 'cancel') {
    active?.abort();
    return;
  }

  if (active) {
    post({
      type: 'error',
      code: 'failed',
      message: 'A sanitization run is already active.',
    });
    return;
  }

  const controller = new AbortController();
  active = controller;

  void runSanitization(event.data, controller.signal, (bytesRead, totalBytes) => {
    post({ type: 'progress', bytesRead, totalBytes });
  })
    .then((result) => post({ type: 'complete', result }))
    .catch((error: unknown) => {
      if (controller.signal.aborted) {
        post({ type: 'cancelled' });
      } else if (error instanceof InvalidUtf8Error) {
        post({ type: 'error', code: 'invalid-utf8', message: error.message });
      } else if (error instanceof DOMException && error.name === 'NotAllowedError') {
        post({
          type: 'error',
          code: 'disk-unavailable',
          message: 'The browser could not write to the selected output file.',
        });
      } else if (error instanceof DOMException && error.name === 'QuotaExceededError') {
        post({
          type: 'error',
          code: 'quota',
          message: 'There is not enough space for the sanitized output.',
        });
      } else {
        post({
          type: 'error',
          code: 'failed',
          message: 'Sanitization failed. The original input was not modified.',
        });
      }
    })
    .finally(() => {
      active = undefined;
    });
});
```

- [ ] **Step 6: Run tests and type-check the worker**

Run:

```bash
bun run test
bunx tsc --noEmit
```

Expected: all tests PASS and TypeScript reports no errors. Fix types without weakening `strict` or adding `skipLibCheck`.

- [ ] **Step 7: Commit Task 2**

```bash
git add src/protocol.ts src/sanitization.ts src/sanitize.worker.ts tests/app.test.ts
git commit -m "feat: add streaming sanitizer worker"
```

---

### Task 3: Accessible Focused-Flow Interface

**Files:**
- Create: `index.html`
- Create: `src/main.ts`
- Create: `src/styles.css`
- Modify: `tests/app.test.ts`

**Interfaces:**
- Consumes: all Task 1 policy exports and Task 2's `WorkerRequest`, `WorkerResponse`, `CompleteResult`, and `WritableFileHandleLike`.
- Produces: the complete upload/paste, rules, progress, preview, copy/download, cancellation, and Clear session workflow.

- [ ] **Step 1: Add a failing semantic-shell test**

Add this import to `tests/app.test.ts`:

```ts
import { readFile } from 'node:fs/promises';
```

Append:

```ts
describe('page shell', () => {
  it('contains the privacy boundary and every workflow landmark', async () => {
    const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
    expect(html).toContain("connect-src 'none'");
    for (const id of [
      'file-input',
      'paste-input',
      'rules-grid',
      'aggressive',
      'sanitize',
      'cancel',
      'status',
      'results',
      'before-preview',
      'after-preview',
      'copy-result',
      'download-result',
      'clear-session',
    ]) {
      expect(html).toContain(`id="${id}"`);
    }
  });
});
```

Vitest transpiles this test; keep tests outside `tsconfig.json` so no additional Node typings dependency is needed.

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
bun run test
```

Expected: FAIL with an `ENOENT` error for `index.html`.

- [ ] **Step 3: Create the semantic page shell**

Create `index.html` with this structure and exact IDs:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'self'; connect-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'"
    >
    <title>Log Sanitizer</title>
    <script type="module" src="/src/main.ts"></script>
  </head>
  <body>
    <header class="site-header">
      <div>
        <p class="eyebrow">Local privacy utility</p>
        <h1>Log Sanitizer</h1>
      </div>
      <div class="header-actions">
        <details>
          <summary id="privacy-status">Processed entirely in this browser</summary>
          <p>Inputs and results are never uploaded. Only a random replacement key is kept in this tab through refreshes.</p>
        </details>
        <button id="clear-session" class="secondary" type="button">Clear session</button>
      </div>
    </header>

    <main>
      <section aria-labelledby="input-heading">
        <p class="step">Step 1</p>
        <h2 id="input-heading">Add content</h2>
        <fieldset class="mode-switch">
          <legend>Input type</legend>
          <label><input id="mode-file" type="radio" name="mode" value="file" checked> Upload file</label>
          <label><input id="mode-text" type="radio" name="mode" value="text"> Paste text</label>
        </fieldset>
        <div id="file-panel">
          <label id="drop-zone" class="drop-zone" for="file-input">
            <strong>Drop one file here</strong>
            <span>or choose a UTF-8 text file</span>
          </label>
          <input id="file-input" type="file">
          <p id="file-name" class="hint"></p>
          <p id="file-limit" class="hint"></p>
        </div>
        <div id="text-panel" hidden>
          <label for="paste-input">Incident notes or log text</label>
          <textarea id="paste-input" rows="12" spellcheck="false"></textarea>
          <p id="paste-limit" class="hint">Maximum pasted input: 50 MiB of UTF-8 text.</p>
        </div>
      </section>

      <section aria-labelledby="rules-heading">
        <p class="step">Step 2</p>
        <div class="section-heading">
          <h2 id="rules-heading">Choose rules</h2>
          <button id="toggle-rules" class="link-button" type="button">Clear all</button>
        </div>
        <div id="rules-grid" class="rules-grid"></div>
        <label class="aggressive">
          <input id="aggressive" type="checkbox">
          <span><strong>Aggressive detection</strong><small>Broader matching may redact benign values.</small></span>
        </label>
      </section>

      <section aria-labelledby="run-heading">
        <p class="step">Step 3</p>
        <h2 id="run-heading">Sanitize locally</h2>
        <div class="run-actions">
          <button id="sanitize" class="primary" type="button">Sanitize locally</button>
          <button id="cancel" class="secondary" type="button" hidden>Cancel</button>
        </div>
        <div id="progress-wrapper" hidden>
          <progress id="progress" max="100" value="0"></progress>
        </div>
        <p id="status" role="status" aria-live="polite"></p>
        <p id="error" class="error" role="alert" tabindex="-1" hidden></p>
      </section>

      <section id="results" aria-labelledby="results-heading" hidden>
        <p class="step">Result</p>
        <h2 id="results-heading" tabindex="-1">Sanitization complete</h2>
        <p><strong id="total-matches">0</strong> replacements across <strong id="line-count">0</strong> lines.</p>
        <ul id="counts-list" class="counts"></ul>
        <div class="preview-grid">
          <div><h3>Before</h3><pre id="before-preview"></pre></div>
          <div><h3>After</h3><pre id="after-preview"></pre></div>
        </div>
        <p id="preview-note" class="hint"></p>
        <div class="run-actions">
          <button id="copy-result" class="primary" type="button" hidden>Copy result</button>
          <button id="download-result" class="primary" type="button" hidden>Download result</button>
        </div>
      </section>
    </main>

    <footer>
      Powered by <a href="https://github.com/socprime/logtotal-sanitizer" rel="noreferrer">SOC Prime LogTotal Sanitizer</a> (Apache-2.0).
    </footer>
  </body>
</html>
```

- [ ] **Step 4: Add the focused-flow CSS without a design dependency**

Create `src/styles.css`:

```css
:root {
  color-scheme: light dark;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #172033;
  background: #f4f6fa;
  --surface: #ffffff;
  --border: #cbd5e1;
  --muted: #5f6b7a;
  --accent: #3157d5;
  --accent-dark: #2444ad;
  --safe: #176b43;
  --danger: #b42318;
}

* { box-sizing: border-box; }
body { margin: 0; min-width: 320px; line-height: 1.5; }
button, input, textarea { font: inherit; }
button { cursor: pointer; }
button:disabled { cursor: not-allowed; opacity: 0.55; }
button:focus-visible, input:focus-visible, textarea:focus-visible, summary:focus-visible, a:focus-visible {
  outline: 3px solid #7c9cff;
  outline-offset: 2px;
}
.site-header, main, footer { width: min(1100px, calc(100% - 2rem)); margin-inline: auto; }
.site-header { display: flex; justify-content: space-between; gap: 2rem; align-items: center; padding-block: 2rem 1rem; }
.header-actions { display: flex; gap: 1rem; align-items: center; }
.header-actions details { max-width: 25rem; color: var(--safe); }
.header-actions details p { color: var(--muted); }
h1, h2, h3, p { margin-top: 0; }
.eyebrow, .step { color: var(--accent); font-size: 0.78rem; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; }
section { background: var(--surface); border: 1px solid var(--border); border-radius: 0.8rem; padding: 1.4rem; margin-block: 1rem; }
.section-heading, .run-actions { display: flex; justify-content: space-between; gap: 1rem; align-items: center; }
.mode-switch { display: flex; gap: 1rem; border: 0; padding: 0; margin-bottom: 1rem; }
.mode-switch legend { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
.drop-zone { display: grid; place-items: center; min-height: 9rem; border: 2px dashed var(--border); border-radius: 0.65rem; text-align: center; }
.drop-zone.dragging { border-color: var(--accent); background: #eef2ff; }
#file-input { display: block; margin-top: 0.8rem; }
textarea { width: 100%; resize: vertical; padding: 0.8rem; border: 1px solid var(--border); border-radius: 0.45rem; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.rules-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.7rem; }
.rule, .aggressive { display: flex; gap: 0.65rem; align-items: flex-start; padding: 0.75rem; border: 1px solid var(--border); border-radius: 0.5rem; }
.rule small, .aggressive small { display: block; color: var(--muted); }
.aggressive { margin-top: 0.8rem; }
.primary, .secondary, .link-button { border-radius: 0.45rem; padding: 0.65rem 0.9rem; }
.primary { color: white; background: var(--accent); border: 1px solid var(--accent); font-weight: 700; }
.primary:hover { background: var(--accent-dark); }
.secondary { background: transparent; border: 1px solid var(--border); }
.link-button { color: var(--accent); background: transparent; border: 0; }
progress { width: 100%; margin-top: 1rem; }
.hint { color: var(--muted); font-size: 0.9rem; }
.error { color: var(--danger); font-weight: 700; }
.counts { display: flex; flex-wrap: wrap; gap: 0.5rem 1.2rem; padding-left: 1.2rem; }
.preview-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
pre { min-height: 12rem; max-height: 28rem; overflow: auto; padding: 1rem; border: 1px solid var(--border); border-radius: 0.5rem; background: #101828; color: #f8fafc; white-space: pre-wrap; overflow-wrap: anywhere; }
pre mark { background: #fbbf24; color: #111827; }
footer { padding-block: 1.5rem 3rem; color: var(--muted); }
[hidden] { display: none !important; }

@media (max-width: 720px) {
  .site-header, .header-actions, .section-heading { align-items: stretch; flex-direction: column; }
  .preview-grid { grid-template-columns: 1fr; }
}

@media (prefers-color-scheme: dark) {
  :root { color: #eef2ff; background: #0f172a; --surface: #182235; --border: #475569; --muted: #b2bdcc; --accent: #8ca5ff; --accent-dark: #6f8cf4; --safe: #78d6a8; }
  .primary { color: #111827; }
  .drop-zone.dragging { background: #26334d; }
}
```

- [ ] **Step 5: Wire the interface to the worker**

Create `src/main.ts`. Keep all DOM orchestration in this file and use the protocol rather than introducing an application state framework. The required state and helpers are:

```ts
import './styles.css';
import {
  MEMORY_LIMIT_BYTES,
  PREVIEW_LINES,
  RULES,
  getOrCreateSessionKey,
  isProbablyBinary,
  limitPreviewSegments,
  orderRuleIds,
  outputFileName,
  replaceSessionKey,
  validateInputSize,
  type StorageLike,
} from './policy';
import type {
  CompleteResult,
  ReportSummary,
  StartMessage,
  WorkerRequest,
  WorkerResponse,
  WritableFileHandleLike,
} from './protocol';

type PickerWindow = Window & {
  showSaveFilePicker?: (options: { suggestedName: string }) => Promise<WritableFileHandleLike>;
};

const showSaveFilePicker = (window as PickerWindow).showSaveFilePicker?.bind(window);

function byId<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing #${id}`);
  return value as T;
}

const fileInput = byId<HTMLInputElement>('file-input');
const pasteInput = byId<HTMLTextAreaElement>('paste-input');
const rulesGrid = byId<HTMLDivElement>('rules-grid');
const aggressive = byId<HTMLInputElement>('aggressive');
const sanitizeButton = byId<HTMLButtonElement>('sanitize');
const cancelButton = byId<HTMLButtonElement>('cancel');
const status = byId<HTMLParagraphElement>('status');
const errorBox = byId<HTMLParagraphElement>('error');
const results = byId<HTMLElement>('results');
const copyButton = byId<HTMLButtonElement>('copy-result');
const downloadButton = byId<HTMLButtonElement>('download-result');
const storage: StorageLike | undefined = (() => {
  try { return window.sessionStorage; } catch { return undefined; }
})();

let keyState = getOrCreateSessionKey(storage);
let worker = createWorker();
let currentResult: CompleteResult | undefined;
let activeRequest: StartMessage | undefined;
let cancelTimer: number | undefined;

function createWorker(): Worker {
  const next = new Worker(new URL('./sanitize.worker.ts', import.meta.url), { type: 'module' });
  next.addEventListener('message', onWorkerMessage as EventListener);
  next.addEventListener('error', () => fail('The sanitizer worker stopped unexpectedly.'));
  return next;
}

function post(message: WorkerRequest): void {
  worker.postMessage(message);
}

function memoryFallback(request: StartMessage): StartMessage | undefined {
  const size = request.input.kind === 'file'
    ? request.input.blob.size
    : new Blob([request.input.text]).size;
  if (request.destination.kind !== 'disk' || size > MEMORY_LIMIT_BYTES) return undefined;
  return { ...request, destination: { kind: 'memory' } };
}
```

Implement the remaining functions with these exact signatures and behaviors:

```ts
function selectedRules(): string[] {
  return [...rulesGrid.querySelectorAll<HTMLInputElement>('input[type="checkbox"]:checked')]
    .map((input) => input.value);
}

function renderSegments(target: HTMLElement, segments: ReportSummary['preview']['before']): boolean {
  const limited = limitPreviewSegments(segments, PREVIEW_LINES);
  target.replaceChildren();
  for (const segment of limited.segments) {
    const node = document.createElement(segment.changed ? 'mark' : 'span');
    node.textContent = segment.text;
    target.append(node);
  }
  return limited.truncated;
}

function download(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function fail(message: string): void {
  errorBox.textContent = message;
  errorBox.hidden = false;
  errorBox.focus();
  setRunning(false);
}

function setRunning(running: boolean): void {
  sanitizeButton.disabled = running;
  cancelButton.hidden = !running;
  byId<HTMLElement>('progress-wrapper').hidden = !running;
}
```

Complete `src/main.ts` with this event flow:

1. Render `RULES` as checked labels with class `rule`, the rule label in `strong`, and description in `small`.
2. Show `250 MiB with direct-to-disk output` in `#file-limit` when the bound `showSaveFilePicker` function exists; otherwise show `50 MiB in this browser`. If the tab key could not be persisted, change `#privacy-status` to explain that refreshes will generate a new key.
3. Switch `#file-panel` and `#text-panel` from the two radio buttons. Before clearing an unexported `currentResult`, use native `window.confirm('Discard the current sanitized result?')` and revert the radio when declined.
4. On file change or drop, retain only the first file. Read at most the first 64 KiB, call `isProbablyBinary()`, and reject it before starting if it looks binary.
5. On Sanitize, clear prior errors/results, require at least one selected rule, and build a `Blob` for pasted text to obtain its exact UTF-8 byte size. Call `validateInputSize()` before reading the complete input.
6. For a file when the bound `showSaveFilePicker` function exists, call it from the button event with `suggestedName: outputFileName(file.name)` and explain beside the action that the user should keep the distinct sanitized filename. Treat `AbortError` as the user cancelling the save dialog. Use `{ kind: 'disk', handle }`; otherwise use `{ kind: 'memory' }`.
7. Build a `StartMessage` with `orderRuleIds(selectedRules())`, `keyState.key`, and `aggressive.checked`. File input uses `{ kind: 'file', blob: file, outputName: outputFileName(file.name) }`; pasted input uses `{ kind: 'text', text: pasteInput.value, outputName: 'sanitized.txt' }`. Assign it to `activeRequest`, then call `post()` inside `try/catch` so a `DataCloneError` from transferring the file handle is handled locally.
8. If posting a disk request throws `DataCloneError`, or the worker returns `code: 'disk-unavailable'`, call `memoryFallback(activeRequest)`. Automatically restart with that request when it is at most 50 MiB; otherwise show that direct-to-disk output is unavailable and the input exceeds the safe fallback limit. This occurs before sanitization reads the full input.
9. On progress, set the `<progress>` percentage to `Math.floor(bytesRead / totalBytes * 100)` and announce formatted MiB counts in `#status`.
10. On complete, clear `activeRequest`, call `renderReport(result.report)`, store `currentResult`, show Copy only for a text result, show Download for text or Blob results, and focus `#results-heading`. A disk result announces that the chosen file was saved and has no export button.
11. `renderReport()` fills total matches, line count, nonzero counts in `RULES` order, and both previews with `renderSegments()`. `#preview-note` states that the preview is limited when either side was truncated or the processed input exceeded 256 KiB.
12. Copy calls `navigator.clipboard.writeText(currentResult.text)` only after a click. Download converts text to a UTF-8 Blob or uses the returned Blob, then calls `download()`.
13. Cancel posts `{ type: 'cancel' }`, changes status to `Cancelling…`, and starts a 1,500 ms timeout. `cancelled` clears the timeout, terminates and recreates the worker, clears `activeRequest`, discards incomplete results, and announces cancellation. The timeout performs the same reset if no acknowledgement arrives.
14. Clear session uses native confirmation when a result exists, empties both inputs and the result DOM, replaces the key with `replaceSessionKey(storage)`, resets all rule checkboxes and aggressive mode to defaults, and announces that future tokens will differ.
15. Clear all/Select all toggles the rule checkboxes and its own label. Prevent a run, with an inline error, when every rule is clear.
16. Drag events add/remove the `dragging` class and never navigate the browser to the dropped file.

Do not log source text, worker payloads, errors containing input, keys, reports, or outputs to the console.

- [ ] **Step 6: Run automated and production checks**

Run:

```bash
bun run test
bun run build
```

Expected: tests PASS; Vite produces `dist/index.html`, bundled CSS, the main module, and the worker module.

- [ ] **Step 7: Perform the focused UI smoke test**

Run:

```bash
bun run dev -- --host 127.0.0.1
```

In a desktop browser, verify upload/paste switching, rule toggles, a small sample containing an IP and bearer token, progress, preview highlighting, Copy, Download, Clear session, keyboard focus, and responsive stacking below 720 px. The CSP intentionally blocks Vite's hot-reload WebSocket; manually refresh while developing.

- [ ] **Step 8: Commit Task 3**

```bash
git add index.html src/main.ts src/styles.css tests/app.test.ts
git commit -m "feat: add local sanitizer interface"
```

---

### Task 4: GitHub Pages Deployment and Operator Documentation

**Files:**
- Modify: `vite.config.ts`
- Modify: `tests/app.test.ts`
- Create: `.github/workflows/pages.yml`
- Create: `README.md`

**Interfaces:**
- Consumes: the complete production build from Task 3.
- Produces: a repository-path-independent `dist/` bundle and a GitHub Pages workflow using only the compiled static artifact.

- [ ] **Step 1: Add the failing relative-base test**

Add this import to `tests/app.test.ts`:

```ts
import viteConfig from '../vite.config';
```

Append:

```ts
describe('deployment configuration', () => {
  it('uses relative asset URLs for GitHub Pages project paths', () => {
    expect(viteConfig).toMatchObject({ base: './' });
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
bun run test
```

Expected: FAIL because the initial Vite base is `/`.

- [ ] **Step 3: Make the build repository-path independent**

Replace `vite.config.ts` with:

```ts
import { defineConfig } from 'vite';

export default defineConfig({ base: './' });
```

- [ ] **Step 4: Add the Pages workflow**

Create `.github/workflows/pages.yml`:

```yaml
name: Deploy GitHub Pages

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  build-and-deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: oven-sh/setup-bun@v2
        with:
          bun-version: 1.4.0
      - run: bun ci
      - run: bun run test
      - run: bun run build
      - uses: actions/configure-pages@v6
      - uses: actions/upload-pages-artifact@v5
        with:
          path: dist
      - id: deployment
        uses: actions/deploy-pages@v5
```

- [ ] **Step 5: Document operation and privacy boundaries**

Create `README.md` with these sections and facts:

```markdown
# Log Sanitizer

A browser-local interface for [SOC Prime LogTotal Sanitizer](https://github.com/socprime/logtotal-sanitizer). Upload one UTF-8 log file or paste incident notes, select built-in redaction rules, inspect a bounded preview, and export the result.

## Privacy

Input, output, replacement values, and reports remain in the browser. The app has no backend, telemetry, analytics, runtime CDN imports, or application-initiated network requests. A random HMAC key is stored only in the current tab's `sessionStorage` so replacements remain consistent through refreshes; Clear session replaces it.

The browser still requests the static application files from GitHub Pages when the page loads. Following the source-library link navigates away only after a user click.

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
```

- [ ] **Step 6: Run the complete automated check and inspect the bundle**

Run:

```bash
bun run test
bun run build
rg -n 'fetch\(|XMLHttpRequest|sendBeacon|WebSocket' src
rg -n '="/assets/' dist/index.html
rg -n '="\./assets/' dist/index.html
```

Expected: tests and build PASS; the first two `rg` checks return no matches; the final check finds the relative built assets. The only `https://` string in `index.html` is the user-clicked source-library link.

- [ ] **Step 7: Commit Task 4**

```bash
git add vite.config.ts tests/app.test.ts .github/workflows/pages.yml README.md
git commit -m "ci: deploy sanitizer to GitHub Pages"
```

---

## End-to-End Acceptance Before Completion

- [ ] Run the clean-install check from a fresh dependency tree:

```bash
bun ci
bun run test
bun run build
git status --short
```

Expected: install, tests, and build succeed; Git shows no generated or unexpected tracked changes.

- [ ] Create two local UTF-8 fixtures without adding them to the repository:

```bash
node -e 'const fs=require("fs");const path=process.argv[1];const limit=Number(process.argv[2]);const fd=fs.openSync(path,"w");let bytes=0,index=0;while(bytes<limit){const line=`event=${index} user=user${index}@example.test src=10.${index%250}.${Math.floor(index/250)%250}.${Math.floor(index/62500)%250} token=Bearer abcdefghijklmnop${index}\n`;bytes+=fs.writeSync(fd,line);index+=1;}fs.closeSync(fd);' /private/tmp/log-sanitizer-250m.log 262144000
node -e 'const fs=require("fs");const path=process.argv[1];const limit=Number(process.argv[2]);const fd=fs.openSync(path,"w");const line="user=alice@example.test src=10.0.0.7 token=Bearer abcdefghijklmnop\n";let bytes=0;while(bytes<limit)bytes+=fs.writeSync(fd,line);fs.closeSync(fd);' /private/tmp/log-sanitizer-50m.log 52428800
```

- [ ] Serve on localhost and perform the browser matrix:

```bash
bun run dev -- --host 127.0.0.1
```

Chrome and Edge must advertise the 250 MiB tier, sanitize `/private/tmp/log-sanitizer-250m.log` to a newly chosen destination, keep the interface responsive, show a bounded preview, and produce a valid sanitized file. Firefox and Safari must advertise the 50 MiB tier, reject the 250 MiB fixture before processing, and successfully sanitize `/private/tmp/log-sanitizer-50m.log` through the Blob download path.

If either direct-to-disk browser fails at 250 MiB, repeat with 200 MiB, 150 MiB, and 100 MiB fixtures in descending order. Change `DIRECT_LIMIT_BYTES`, its test expectation, the design spec, and README to the largest size that passes in both browsers; use 50 MiB if none pass. Commit that correction as `fix: align file limit with browser acceptance`.

- [ ] Exercise a small file and pasted note containing a bearer token, IPv4 address, hostname, email, payment-shaped value, and home path. Verify every enabled rule count, stable tokens across two runs and one refresh, changed tokens after Clear session, Copy, Download, output naming, and source-file preservation.

- [ ] Cancel one direct-to-disk run and one Blob run. Confirm the UI returns to idle, incomplete results are unavailable, a new run succeeds, and no source file is changed.

- [ ] Use keyboard-only navigation at desktop and narrow widths. Confirm visible focus, logical order, live progress/completion announcements, focused errors, focused results, and stacked previews below 720 px.

- [ ] Keep browser developer tools on the Network panel during upload, paste, sanitize, preview, copy, download, cancellation, refresh, and Clear session. Confirm there are no input-dependent or application-initiated network requests. Initial same-origin static asset requests and a deliberate click on the source-library link are the only expected network activity.

- [ ] Run the final evidence check:

```bash
bun run test
bun run build
git status --short --branch
git log --oneline --decorate -5
```

Expected: tests and build succeed, the working tree is clean, and the four task commits plus the design/plan documentation commits are visible.
