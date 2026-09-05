import { describe, expect, it } from 'vitest';
import { sanitizeText } from '@socprime/logtotal-sanitizer';
import { strictUtf8Source, runSanitization } from '../src/sanitization';
import type { StartMessage, WritableFileHandleLike } from '../src/protocol';
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
