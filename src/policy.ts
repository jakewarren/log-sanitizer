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
