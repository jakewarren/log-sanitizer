import {
  createSanitizer,
  generateKey,
  getBuiltinRule,
  type SanitizeReport,
  type SanitizeRule,
  type SanitizeSegment,
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
  signal?: AbortSignal,
): AsyncGenerator<string> {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  try {
    for (let offset = 0; offset < blob.size; offset += chunkBytes) {
      if (signal?.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
      const end = Math.min(offset + chunkBytes, blob.size);
      const bytes = new Uint8Array(await blob.slice(offset, end).arrayBuffer());
      if (signal?.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
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

function clampPreview(segments: readonly SanitizeSegment[]): SanitizeSegment[] {
  const encoder = new TextEncoder();
  const limited: SanitizeSegment[] = [];
  let remaining = PREVIEW_BYTES;
  for (const segment of segments) {
    if (remaining === 0) break;
    let chars = 0;
    let bytes = 0;
    for (const character of segment.text) {
      const characterBytes = encoder.encode(character).byteLength;
      if (bytes + characterBytes > remaining) break;
      bytes += characterBytes;
      chars += character.length;
    }
    if (chars > 0) limited.push({ text: segment.text.slice(0, chars), changed: segment.changed });
    remaining -= bytes;
  }
  return limited;
}

function summarize(
  report: SanitizeReport,
  includeLegend: boolean,
  simplify: (value: string) => string,
): ReportSummary {
  return {
    counts: report.counts,
    totalMatches: report.totalMatches,
    lineCount: report.lineCount,
    ...(includeLegend ? {
      replacements: report.replacements.map((entry) => ({
        ...entry,
        replacement: simplify(entry.replacement),
      })),
    } : {}),
    preview: {
      before: clampPreview(report.preview.before),
      after: clampPreview(report.preview.after.map((segment) => ({
        ...segment,
        text: simplify(segment.text),
      }))),
    },
  };
}

function simplifiedRules(ruleIds: StartMessage['rules']): {
  rules: SanitizeRule[];
  simplify: (value: string) => string;
} {
  const categories = new Map<string, string>();
  const marker = generateKey().slice(0, 16).toUpperCase();
  const rules = ruleIds.map((id, index) => {
    const rule = getBuiltinRule(id)!;
    const category = rule.token ?? id.toUpperCase();
    const token = `LS${marker}${index}`;
    categories.set(token, category.replace(/_/g, ' '));
    return { ...rule, mode: 'pseudo' as const, token };
  });
  return {
    rules,
    simplify: (value) => value.replace(
      /<([A-Z][A-Z0-9]*):[0-9a-f]{16}>/g,
      (replacement, token: string) => categories.has(token)
        ? `<REDACTED ${categories.get(token)}>`
        : replacement,
    ),
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
  }, CHUNK_BYTES, signal);
  const simplified = message.simplifyReplacements
    ? simplifiedRules(message.rules)
    : { rules: message.rules, simplify: (value: string) => value };
  const sanitizer = createSanitizer({
    key: message.key,
    keyEncoding: 'hex',
    rules: simplified.rules,
    aggressive: message.aggressive,
    report: { previewBytes: PREVIEW_BYTES, replacements: message.includeLegend === true, contextChars: 0 },
  });

  let writable: WritableFileLike | undefined;
  const memory = message.destination.kind === 'memory' ? memorySink() : undefined;
  const outputSink: TextSink = message.destination.kind === 'disk'
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
  const sink: TextSink = message.simplifyReplacements
    ? {
        write(chunk) {
          return outputSink.write(simplified.simplify(chunk));
        },
        close() {
          return outputSink.close?.();
        },
      }
    : outputSink;

  try {
    if (message.destination.kind === 'disk') {
      writable = await message.destination.handle.createWritable();
    }
    const report = await sanitizer.sanitizeStream(source, sink, {
      signal,
      onProgress: () => onProgress(bytesRead, blob.size),
    });
    const summary = summarize(report, message.includeLegend === true, simplified.simplify);

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
