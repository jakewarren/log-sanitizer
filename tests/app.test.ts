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
