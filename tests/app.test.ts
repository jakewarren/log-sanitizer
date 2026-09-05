import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFile } from 'node:fs/promises';
import { Window } from 'happy-dom';
import { sanitizeText } from '@socprime/logtotal-sanitizer';
import { strictUtf8Source, runSanitization } from '../src/sanitization';
import type { StartMessage, WritableFileHandleLike } from '../src/protocol';
import viteConfig from '../vite.config';
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
  RULES,
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

describe('deployment configuration', () => {
  it('uses relative asset URLs for GitHub Pages project paths', () => {
    expect(viteConfig).toMatchObject({ base: './' });
  });
});

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

  it('clamps each long single-line preview to UTF-8 bytes without splitting multibyte text', async () => {
    const request: StartMessage = {
      type: 'start',
      key: '11'.repeat(32),
      rules: ['ips'],
      aggressive: false,
      input: { kind: 'text', text: `from 10.0.0.7 ${'é'.repeat(200_000)}`, outputName: 'sanitized.txt' },
      destination: { kind: 'memory' },
    };
    const result = await runSanitization(request, new AbortController().signal, () => undefined);
    const utf8 = new TextEncoder();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    if (result.kind !== 'text') throw new Error('Expected text result');
    for (const side of [result.report.preview.before, result.report.preview.after]) {
      const text = side.map((segment) => segment.text).join('');
      expect(utf8.encode(text).byteLength).toBeLessThanOrEqual(256 * 1024);
      expect(decoder.decode(utf8.encode(text))).toBe(text);
      expect(side.some((segment) => segment.changed)).toBe(true);
    }
  });

  it('clamps a long ASCII single-line preview on both sides', async () => {
    const request: StartMessage = {
      type: 'start',
      key: '11'.repeat(32),
      rules: ['ips'],
      aggressive: false,
      input: { kind: 'text', text: 'a'.repeat(300_000), outputName: 'sanitized.txt' },
      destination: { kind: 'memory' },
    };
    const result = await runSanitization(request, new AbortController().signal, () => undefined);
    const utf8 = new TextEncoder();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    if (result.kind !== 'text') throw new Error('Expected text result');
    for (const side of [result.report.preview.before, result.report.preview.after]) {
      const text = side.map((segment) => segment.text).join('');
      expect(utf8.encode(text).byteLength).toBeLessThanOrEqual(262_144);
      expect(decoder.decode(utf8.encode(text))).toBe(text);
    }
  });

  it('preserves unchanged and changed flags while clamping mixed preview segments', async () => {
    const request: StartMessage = {
      type: 'start',
      key: '11'.repeat(32),
      rules: ['ips'],
      aggressive: false,
      input: { kind: 'text', text: `from 10.0.0.7 ${'a'.repeat(300_000)}`, outputName: 'sanitized.txt' },
      destination: { kind: 'memory' },
    };
    const result = await runSanitization(request, new AbortController().signal, () => undefined);
    const utf8 = new TextEncoder();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    if (result.kind !== 'text') throw new Error('Expected text result');
    for (const side of [result.report.preview.before, result.report.preview.after]) {
      const text = side.map((segment) => segment.text).join('');
      expect(utf8.encode(text).byteLength).toBeLessThanOrEqual(262_144);
      expect(decoder.decode(utf8.encode(text))).toBe(text);
      expect(side.some((segment) => !segment.changed)).toBe(true);
      expect(side.some((segment) => segment.changed)).toBe(true);
    }
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

  it('aborts an active disk run without closing and permits a subsequent run', async () => {
    class ReadCountingBlob {
      readonly size: number;
      reads = 0;

      constructor(
        private readonly bytes: Uint8Array,
        private readonly root: ReadCountingBlob = this,
      ) {
        this.size = bytes.byteLength;
      }

      slice(start = 0, end = this.size): ReadCountingBlob {
        return new ReadCountingBlob(this.bytes.slice(start, end), this.root);
      }

      async arrayBuffer(): Promise<ArrayBuffer> {
        this.root.reads += 1;
        return this.bytes.slice().buffer;
      }
    }

    const firstController = new AbortController();
    const firstBlob = new ReadCountingBlob(
      new TextEncoder().encode(`from 10.0.0.7 ${'x'.repeat(4 * 1024 * 1024)}`),
    );
    let firstClosed = false;
    let firstAborted = false;
    const firstHandle: WritableFileHandleLike = {
      async createWritable() {
        return {
          async write() {
            firstController.abort();
          },
          async close() {
            firstClosed = true;
          },
          async abort() {
            firstAborted = true;
          },
        };
      },
    };
    const firstRequest: StartMessage = {
      type: 'start',
      key: '11'.repeat(32),
      rules: ['ips'],
      aggressive: false,
      input: { kind: 'file', blob: firstBlob as unknown as Blob, outputName: 'active.log' },
      destination: { kind: 'disk', handle: firstHandle },
    };

    let progressCalls = 0;
    await expect(
      runSanitization(firstRequest, firstController.signal, () => {
        progressCalls += 1;
        if (progressCalls === 1) firstController.abort();
      }),
    ).rejects.toThrow();
    expect(progressCalls).toBe(1);
    expect(firstBlob.reads).toBe(1);
    expect(firstClosed).toBe(false);
    expect(firstAborted).toBe(true);

    let secondClosed = false;
    let secondAborted = false;
    const secondHandle: WritableFileHandleLike = {
      async createWritable() {
        return {
          async write() {},
          async close() {
            secondClosed = true;
          },
          async abort() {
            secondAborted = true;
          },
        };
      },
    };
    const secondRequest: StartMessage = {
      ...firstRequest,
      input: { kind: 'file', blob: new Blob(['from 10.0.0.7']), outputName: 'next.log' },
      destination: { kind: 'disk', handle: secondHandle },
    };
    const secondResult = await runSanitization(
      secondRequest,
      new AbortController().signal,
      () => undefined,
    );
    expect(secondResult.kind).toBe('disk');
    expect(secondClosed).toBe(true);
    expect(secondAborted).toBe(false);
  });
});

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

describe('DOM run lifecycle', () => {
  class TestWorker {
    static instances: TestWorker[] = [];
    static postFailures = 0;
    readonly messages: unknown[] = [];
    terminated = false;
    private readonly listeners = new Map<string, Array<(event: unknown) => void>>();

    constructor() {
      TestWorker.instances.push(this);
    }

    addEventListener(type: string, listener: (event: unknown) => void): void {
      this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    postMessage(message: unknown): void {
      this.messages.push(message);
      if (TestWorker.postFailures > 0) {
        TestWorker.postFailures -= 1;
        throw new DOMException('Cannot clone', 'DataCloneError');
      }
    }

    terminate(): void {
      this.terminated = true;
    }

    emit(data: WorkerResponse): void {
      for (const listener of this.listeners.get('message') ?? []) listener({ data });
    }
  }

  let appWindow: Window;
  let appDocument: Document;
  const complete = (kind: 'blob' | 'disk' = 'blob'): WorkerResponse => ({
    type: 'complete',
    result: kind === 'disk'
      ? { kind, report: { counts: {}, totalMatches: 0, lineCount: 1, preview: { before: [], after: [] } } }
      : { kind, blob: new Blob(['done']), fileName: 'sample.sanitized.log', report: { counts: {}, totalMatches: 0, lineCount: 1, preview: { before: [], after: [] } } },
  });

  const completeText = (): WorkerResponse => ({
    type: 'complete',
    result: { kind: 'text', text: 'sanitized', fileName: 'sanitized.txt', report: { counts: {}, totalMatches: 0, lineCount: 1, preview: { before: [], after: [] } } },
  });

  async function settle(): Promise<void> {
    for (let index = 0; index < 5; index += 1) await Promise.resolve();
  }

  function click(id: string): void {
    appDocument.getElementById(id)?.dispatchEvent(new appWindow.Event('click', { bubbles: true }));
  }

  function setFile(): void {
    const input = appDocument.getElementById('file-input') as HTMLInputElement;
    Object.defineProperty(input, 'files', { configurable: true, value: [new appWindow.File(['from 10.0.0.7'], 'sample.log')] });
    input.dispatchEvent(new appWindow.Event('change', { bubbles: true }));
  }

  beforeAll(async () => {
    appWindow = new Window({ url: 'http://localhost/' });
    const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
    appDocument = appWindow.document;
    appDocument.body.innerHTML = html.slice(html.indexOf('<body>') + 6, html.indexOf('</body>'));
    vi.stubGlobal('window', appWindow);
    vi.stubGlobal('document', appDocument);
    vi.stubGlobal('Worker', TestWorker);
    vi.stubGlobal('DOMException', appWindow.DOMException);
    vi.stubGlobal('Blob', appWindow.Blob);
    vi.stubGlobal('File', appWindow.File);
    Object.defineProperty(appWindow, 'showSaveFilePicker', { configurable: true, value: vi.fn(async () => ({ createWritable: vi.fn() })) });
    appWindow.confirm = () => true;
    await import('../src/main');
  });

  beforeEach(() => {
    TestWorker.instances.length = 0;
    TestWorker.postFailures = 0;
    (appDocument.getElementById('paste-input') as HTMLTextAreaElement).value = '';
    click('clear-session');
  });

  it('retries a DataCloneError disk request through memory for a small file', async () => {
    TestWorker.postFailures = 1;
    setFile();
    click('sanitize');
    await settle();
    expect(TestWorker.instances).toHaveLength(2);
    const retry = TestWorker.instances[1];
    expect((retry.messages[0] as StartMessage).destination).toEqual({ kind: 'memory' });
    retry.emit(complete());
    await settle();
    expect((appDocument.getElementById('results') as HTMLElement).hidden).toBe(false);
  });

  it('retries a worker disk-unavailable response through memory', async () => {
    setFile();
    click('sanitize');
    await settle();
    const first = TestWorker.instances[0];
    expect((first.messages[0] as StartMessage).destination.kind).toBe('disk');
    first.emit({ type: 'error', code: 'disk-unavailable', message: 'unavailable' });
    await settle();
    expect(TestWorker.instances).toHaveLength(2);
    expect((TestWorker.instances[1].messages[0] as StartMessage).destination).toEqual({ kind: 'memory' });
  });

  it('ignores late messages from the retired disk worker during memory retry', async () => {
    setFile();
    click('sanitize');
    await settle();
    const first = TestWorker.instances[0];
    first.emit({ type: 'error', code: 'disk-unavailable', message: 'unavailable' });
    await settle();
    const retry = TestWorker.instances[1];
    first.emit({ type: 'progress', bytesRead: 1, totalBytes: 1 });
    first.emit(complete('disk'));
    first.emit({ type: 'error', code: 'failed', message: 'late failure' });
    await settle();
    expect((appDocument.getElementById('results') as HTMLElement).hidden).toBe(true);
    expect((appDocument.getElementById('status') as HTMLElement).textContent).toContain('retrying');
    retry.emit(complete());
    await settle();
    expect((appDocument.getElementById('results') as HTMLElement).hidden).toBe(false);
  });

  it('ignores a late completion from a worker retired by Clear session', async () => {
    setFile();
    click('sanitize');
    await settle();
    const first = TestWorker.instances[0];
    click('clear-session');
    first.emit(complete());
    await settle();
    expect((appDocument.getElementById('results') as HTMLElement).hidden).toBe(true);
    expect((appDocument.getElementById('status') as HTMLElement).textContent).toContain('Session cleared');
  });

  it('keeps cancellation active through 1,499 ms and retires at 1,500 ms', async () => {
    vi.useFakeTimers();
    const timerWindow = appWindow as unknown as { setTimeout: typeof setTimeout; clearTimeout: typeof clearTimeout };
    timerWindow.setTimeout = globalThis.setTimeout;
    timerWindow.clearTimeout = globalThis.clearTimeout;
    try {
      setFile();
      click('sanitize');
      await settle();
      click('cancel');
      expect((appDocument.getElementById('status') as HTMLElement).textContent).toBe('Cancelling…');
      vi.advanceTimersByTime(1499);
      expect((appDocument.getElementById('cancel') as HTMLButtonElement).hidden).toBe(false);
      expect((appDocument.getElementById('cancel') as HTMLButtonElement).disabled).toBe(true);
      vi.advanceTimersByTime(1);
      const cancel = appDocument.getElementById('cancel') as HTMLButtonElement;
      expect(cancel.hidden).toBe(true);
      expect(cancel.disabled).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('clears an acknowledged cancellation timer before the next run', async () => {
    vi.useFakeTimers();
    const timerWindow = appWindow as unknown as { setTimeout: typeof setTimeout; clearTimeout: typeof clearTimeout };
    timerWindow.setTimeout = globalThis.setTimeout;
    timerWindow.clearTimeout = globalThis.clearTimeout;
    try {
      setFile();
      click('sanitize');
      await settle();
      const first = TestWorker.instances[0];
      click('cancel');
      first.emit({ type: 'cancelled' });
      await settle();
      expect(vi.getTimerCount()).toBe(0);
      vi.advanceTimersByTime(5000);
      setFile();
      click('sanitize');
      await settle();
      expect(TestWorker.instances).toHaveLength(2);
      expect((appDocument.getElementById('cancel') as HTMLButtonElement).hidden).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('claims delayed file preflight synchronously so a double click starts one run', async () => {
    const resolvers: Array<(handle: WritableFileHandleLike) => void> = [];
    const picker = vi.fn(() => new Promise<WritableFileHandleLike>((resolve) => resolvers.push(resolve)));
    (appWindow.showSaveFilePicker as ReturnType<typeof vi.fn>).mockImplementation(picker);
    try {
      setFile();
      click('sanitize');
      click('sanitize');
      expect(picker).toHaveBeenCalledTimes(1);
      expect((appDocument.getElementById('sanitize') as HTMLButtonElement).disabled).toBe(true);
      resolvers[0]({ createWritable: vi.fn(async () => ({ write: vi.fn(), close: vi.fn(), abort: vi.fn() })) });
      await settle();
      expect(TestWorker.instances).toHaveLength(1);
    } finally {
      (appWindow.showSaveFilePicker as ReturnType<typeof vi.fn>).mockImplementation(async () => ({ createWritable: vi.fn() }));
    }
  });

  it('encodes pasted input once for size, binary sampling, and run bytes', async () => {
    const NativeTextEncoder = globalThis.TextEncoder;
    let fullEncodes = 0;
    class CountingTextEncoder extends NativeTextEncoder {
      override encode(input = ''): Uint8Array {
        if (input === 'from 10.0.0.7') fullEncodes += 1;
        return super.encode(input);
      }
    }
    vi.stubGlobal('TextEncoder', CountingTextEncoder);
    try {
      const modeText = appDocument.getElementById('mode-text') as HTMLInputElement;
      modeText.checked = true;
      modeText.dispatchEvent(new appWindow.Event('change', { bubbles: true }));
      const paste = appDocument.getElementById('paste-input') as HTMLTextAreaElement;
      paste.value = 'from 10.0.0.7';
      paste.dispatchEvent(new appWindow.Event('input', { bubbles: true }));
      fullEncodes = 0;
      click('sanitize');
      await settle();
      expect(fullEncodes).toBe(1);
    } finally {
      vi.stubGlobal('TextEncoder', NativeTextEncoder);
    }
  });

  it('retires delayed file preflight when Clear session is activated', async () => {
    let resolvePicker!: (handle: WritableFileHandleLike) => void;
    const picker = vi.fn(() => new Promise<WritableFileHandleLike>((resolve) => { resolvePicker = resolve; }));
    (appWindow.showSaveFilePicker as ReturnType<typeof vi.fn>).mockImplementation(picker);
    try {
      setFile();
      click('sanitize');
      click('clear-session');
      resolvePicker({ createWritable: vi.fn(async () => ({ write: vi.fn(), close: vi.fn(), abort: vi.fn() })) });
      await settle();
      expect(TestWorker.instances).toHaveLength(0);
      expect((appDocument.getElementById('status') as HTMLElement).textContent).toContain('Session cleared');
    } finally {
      (appWindow.showSaveFilePicker as ReturnType<typeof vi.fn>).mockImplementation(async () => ({ createWritable: vi.fn() }));
    }
  });

  it('keeps preflight bound to the initially selected file', async () => {
    let resolvePicker!: (handle: WritableFileHandleLike) => void;
    const picker = vi.fn(() => new Promise<WritableFileHandleLike>((resolve) => { resolvePicker = resolve; }));
    (appWindow.showSaveFilePicker as ReturnType<typeof vi.fn>).mockImplementation(picker);
    try {
      setFile();
      click('sanitize');
      const input = appDocument.getElementById('file-input') as HTMLInputElement;
      Object.defineProperty(input, 'files', { configurable: true, value: [new appWindow.File(['replacement'], 'replacement.log')] });
      input.dispatchEvent(new appWindow.Event('change', { bubbles: true }));
      resolvePicker({ createWritable: vi.fn(async () => ({ write: vi.fn(), close: vi.fn(), abort: vi.fn() })) });
      await settle();
      expect(TestWorker.instances).toHaveLength(1);
      expect((TestWorker.instances[0].messages[0] as StartMessage).input).toMatchObject({ kind: 'file', outputName: 'sample.sanitized.log' });
    } finally {
      (appWindow.showSaveFilePicker as ReturnType<typeof vi.fn>).mockImplementation(async () => ({ createWritable: vi.fn() }));
    }
  });

  it('rejects empty pasted input with a focused missing-input error', async () => {
    const modeText = appDocument.getElementById('mode-text') as HTMLInputElement;
    modeText.checked = true;
    modeText.dispatchEvent(new appWindow.Event('change', { bubbles: true }));
    click('sanitize');
    await settle();
    const error = appDocument.getElementById('error') as HTMLElement;
    expect(error.textContent).toBe('Paste or type text before sanitizing.');
    expect(appDocument.activeElement).toBe(error);
    expect(TestWorker.instances).toHaveLength(0);
  });

  it('rejects a text control byte appearing after the first 8 KiB', async () => {
    const modeText = appDocument.getElementById('mode-text') as HTMLInputElement;
    modeText.checked = true;
    modeText.dispatchEvent(new appWindow.Event('change', { bubbles: true }));
    const paste = appDocument.getElementById('paste-input') as HTMLTextAreaElement;
    paste.value = `${'a'.repeat(16 * 1024)}\0`;
    paste.dispatchEvent(new appWindow.Event('input', { bubbles: true }));
    click('sanitize');
    await settle();
    expect((appDocument.getElementById('error') as HTMLElement).textContent).toContain('binary control');
    expect(TestWorker.instances).toHaveLength(0);
  });

  it('samples 64 KiB of a file for binary preflight', async () => {
    const bytes = new Uint8Array(16 * 1024 + 1);
    bytes.fill(0x61);
    bytes[16 * 1024] = 0;
    const input = appDocument.getElementById('file-input') as HTMLInputElement;
    Object.defineProperty(input, 'files', { configurable: true, value: [new appWindow.File([bytes], 'binary.log')] });
    input.dispatchEvent(new appWindow.Event('change', { bubbles: true }));
    click('sanitize');
    await settle();
    expect((appDocument.getElementById('error') as HTMLElement).textContent).toContain('looks binary');
    expect(TestWorker.instances).toHaveLength(0);
  });

  it('renders nonzero rule counts in RULES priority order', async () => {
    setFile();
    click('sanitize');
    await settle();
    TestWorker.instances[0].emit({
      type: 'complete',
      result: { kind: 'blob', blob: new Blob(['done']), fileName: 'sample.sanitized.log', report: { counts: { ips: 2, secrets: 1 }, totalMatches: 3, lineCount: 1, preview: { before: [], after: [] } } },
    });
    await settle();
    const labels = Array.from(appDocument.querySelectorAll('#counts-list li')).map((item) => item.textContent);
    expect(labels).toEqual([RULES.find((rule) => rule.id === 'secrets')!.label + ': 1', RULES.find((rule) => rule.id === 'ips')!.label + ': 2']);
  });

  it('keeps a result when file selection is refused', async () => {
    setFile();
    click('sanitize');
    await settle();
    TestWorker.instances[0].emit(complete());
    await settle();
    appWindow.confirm = () => false;
    const input = appDocument.getElementById('file-input') as HTMLInputElement;
    Object.defineProperty(input, 'files', { configurable: true, value: [new appWindow.File(['replacement'], 'replacement.log')] });
    input.dispatchEvent(new appWindow.Event('change', { bubbles: true }));
    expect((appDocument.getElementById('results') as HTMLElement).hidden).toBe(false);
    expect(TestWorker.instances).toHaveLength(1);
    appWindow.confirm = () => true;
    click('sanitize');
    await settle();
    expect((TestWorker.instances[1].messages[0] as StartMessage).input).toMatchObject({ kind: 'file', outputName: 'sample.sanitized.log' });
  });

  it('clears a result when a dropped file transition is accepted', async () => {
    setFile();
    click('sanitize');
    await settle();
    TestWorker.instances[0].emit(complete());
    await settle();
    const dropEvent = new appWindow.Event('drop', { bubbles: true });
    Object.defineProperty(dropEvent, 'dataTransfer', { value: { files: [new appWindow.File(['replacement'], 'replacement.log')] } });
    appDocument.getElementById('drop-zone')?.dispatchEvent(dropEvent);
    expect((appDocument.getElementById('results') as HTMLElement).hidden).toBe(true);
  });

  it('keeps a result when a pasted edit is refused', async () => {
    const modeText = appDocument.getElementById('mode-text') as HTMLInputElement;
    modeText.checked = true;
    modeText.dispatchEvent(new appWindow.Event('change', { bubbles: true }));
    const paste = appDocument.getElementById('paste-input') as HTMLTextAreaElement;
    paste.value = 'original';
    paste.dispatchEvent(new appWindow.Event('input', { bubbles: true }));
    click('sanitize');
    await settle();
    TestWorker.instances[0].emit(completeText());
    await settle();
    expect((appDocument.getElementById('results') as HTMLElement).hidden).toBe(false);
    expect((appDocument.getElementById('copy-result') as HTMLButtonElement).hidden).toBe(false);
    appWindow.confirm = () => false;
    paste.value = 'replacement';
    paste.dispatchEvent(new appWindow.Event('input', { bubbles: true }));
    expect(paste.value).toBe('original');
    expect((appDocument.getElementById('results') as HTMLElement).hidden).toBe(false);
    expect((appDocument.getElementById('copy-result') as HTMLButtonElement).hidden).toBe(false);
    expect(TestWorker.instances).toHaveLength(1);
    appWindow.confirm = () => true;
  });

  it('reverts a refused mode switch and keeps the result visible', async () => {
    setFile();
    click('sanitize');
    await settle();
    TestWorker.instances[0].emit(complete());
    await settle();
    appWindow.confirm = () => false;
    const modeText = appDocument.getElementById('mode-text') as HTMLInputElement;
    modeText.checked = true;
    modeText.dispatchEvent(new appWindow.Event('change', { bubbles: true }));
    expect((appDocument.getElementById('mode-file') as HTMLInputElement).checked).toBe(true);
    expect((appDocument.getElementById('results') as HTMLElement).hidden).toBe(false);
    appWindow.confirm = () => true;
  });
});
