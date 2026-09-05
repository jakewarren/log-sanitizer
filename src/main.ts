import { PREVIEW_BYTES, RULES, getInputLimit, getOrCreateSessionKey, isProbablyBinary, limitPreviewSegments, orderRuleIds, outputFileName, replaceSessionKey, validateInputSize, type InputKind, type SessionKeyState } from './policy';
import type { CompleteResult, StartMessage, WorkerResponse, WritableFileHandleLike } from './protocol';

type PickerOptions = { suggestedName?: string; types?: Array<{ description: string; accept: Record<string, string[]> }> };
type PickerWindow = Window & { showSaveFilePicker?: (options?: PickerOptions) => Promise<WritableFileHandleLike> };

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const fileInput = $('file-input') as HTMLInputElement;
const pasteInput = $('paste-input') as HTMLTextAreaElement;
const modeFile = $('mode-file') as HTMLInputElement;
const modeText = $('mode-text') as HTMLInputElement;
const filePanel = $('file-panel');
const textPanel = $('text-panel');
const fileName = $('file-name');
const fileLimit = $('file-limit');
const dropZone = $('drop-zone');
const rulesGrid = $('rules-grid');
const aggressive = $('aggressive') as HTMLInputElement;
const sanitizeButton = $('sanitize') as HTMLButtonElement;
const cancelButton = $('cancel') as HTMLButtonElement;
const clearSessionButton = $('clear-session') as HTMLButtonElement;
const toggleRulesButton = $('toggle-rules') as HTMLButtonElement;
const progressWrapper = $('progress-wrapper');
const progress = $('progress') as HTMLProgressElement;
const status = $('status');
const error = $('error');
const results = $('results');
const resultHeading = $('results-heading');
const totalMatches = $('total-matches');
const lineCount = $('line-count');
const countsList = $('counts-list');
const beforePreview = $('before-preview');
const afterPreview = $('after-preview');
const previewNote = $('preview-note');
const copyButton = $('copy-result') as HTMLButtonElement;
const downloadButton = $('download-result') as HTMLButtonElement;
const CANCEL_TIMEOUT_MS = 1500;
const modeControls = [modeFile, modeText];
const inputControls = [fileInput, pasteInput, aggressive];

let selectedFile: File | null = null;
let session: SessionKeyState;
let currentResult: CompleteResult | undefined;
let activeInputKind: InputKind | undefined;
let activeInputBytes = 0;
let pasteValue = '';
let runSequence = 0;

interface ActivePreflight {
  kind: InputKind;
  file: File | null;
}

let activePreflight: ActivePreflight | undefined;

interface ActiveRun {
  id: number;
  request: StartMessage;
  inputBytes: number;
  worker?: Worker;
  cancelTimer?: number;
  cancelRequested: boolean;
}

let activeRun: ActiveRun | undefined;

type WorkerErrorCode = Extract<WorkerResponse, { type: 'error' }>['code'];

function shouldRetryInMemory(code: WorkerErrorCode, inputBytes: number): boolean {
  return code === 'disk-unavailable' && inputBytes <= 50 * 1024 * 1024;
}

function isCurrentRun(runId: number, activeRunId: number | undefined): boolean {
  return activeRunId === runId;
}

function safeSessionStorage(): Storage | undefined {
  try {
    const storage = window.sessionStorage;
    const probe = '__log_sanitizer_probe__';
    storage.setItem(probe, '1');
    storage.removeItem(probe);
    return storage;
  } catch {
    return undefined;
  }
}

const storage = safeSessionStorage();
session = getOrCreateSessionKey(storage);

function canStreamToDisk(): boolean {
  return showSaveFilePicker !== undefined;
}

const showSaveFilePicker = typeof (window as PickerWindow).showSaveFilePicker === 'function'
  ? (window as PickerWindow).showSaveFilePicker!.bind(window)
  : undefined;

function setStatus(message: string): void {
  status.textContent = message;
}

function showError(message: string): void {
  error.textContent = message;
  error.hidden = false;
  error.focus();
}

function clearError(): void {
  error.textContent = '';
  error.hidden = true;
}

function updateLimitText(): void {
  const limit = getInputLimit('file', canStreamToDisk());
  fileLimit.textContent = `Maximum file size: ${limit === 250 * 1024 * 1024 ? '250 MiB with direct-to-disk output' : '50 MiB in-memory output'}.`;
}

function updateMode(): void {
  filePanel.hidden = !modeFile.checked;
  textPanel.hidden = !modeText.checked;
  activeInputKind = modeFile.checked ? 'file' : 'text';
}

function clearResult(): void {
  currentResult = undefined;
  results.hidden = true;
  copyButton.hidden = true;
  downloadButton.hidden = true;
  beforePreview.replaceChildren();
  afterPreview.replaceChildren();
  countsList.replaceChildren();
  previewNote.textContent = '';
}

function hasResult(): boolean {
  return currentResult !== undefined;
}

function allowInputTransition(onCancel: () => void): boolean {
  if (!hasResult()) return true;
  if (!window.confirm('Discard the current sanitized result?')) {
    onCancel();
    return false;
  }
  clearResult();
  return true;
}

function setFile(file: File | undefined): void {
  if (!file || activePreflight) return;
  if (!allowInputTransition(() => { fileInput.value = ''; })) return;
  selectedFile = file;
  pasteInput.value = '';
  pasteValue = '';
  fileName.textContent = `${file.name} (${formatBytes(file.size)}). Suggested output: ${outputFileName(file.name)} — keep the output name distinct from the source.`;
  clearError();
  setStatus('File ready to sanitize locally.');
}

function formatBytes(value: number): string {
  if (value < 1024 * 1024) return `${Math.round(value / 1024)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function renderRules(): void {
  rulesGrid.replaceChildren(...RULES.map((rule) => {
    const label = document.createElement('label');
    label.className = 'rule';
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = rule.id;
    input.checked = true;
    input.addEventListener('change', updateToggleLabel);
    const text = document.createElement('span');
    const strong = document.createElement('strong');
    strong.textContent = rule.label;
    const small = document.createElement('small');
    small.textContent = rule.description;
    text.append(strong, small);
    label.append(input, text);
    return label;
  }));
  updateToggleLabel();
}

function ruleInputs(): HTMLInputElement[] {
  return Array.from(rulesGrid.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'));
}

function updateToggleLabel(): void {
  const inputs = ruleInputs();
  toggleRulesButton.textContent = inputs.every((input) => input.checked) ? 'Clear all' : 'Select all';
}

function setRuleInputsDisabled(disabled: boolean): void {
  ruleInputs().forEach((input) => { input.disabled = disabled; });
}

function renderResult(result: CompleteResult): void {
  currentResult = result;
  const report = result.report;
  totalMatches.textContent = String(report.totalMatches);
  lineCount.textContent = String(report.lineCount);
  countsList.replaceChildren(...RULES.flatMap((rule) => {
    const count = report.counts[rule.id];
    if (!count) return [];
    const item = document.createElement('li');
    item.textContent = `${rule.label}: ${count}`;
    return [item];
  }));
  const beforeLimited = limitPreviewSegments(report.preview.before);
  const afterLimited = limitPreviewSegments(report.preview.after);
  renderSegments(beforePreview, beforeLimited.segments);
  renderSegments(afterPreview, afterLimited.segments);
  previewNote.textContent = activeInputBytes > PREVIEW_BYTES || beforeLimited.truncated || afterLimited.truncated
    ? 'Preview limited to the first 256 KiB and 200 lines.'
    : 'Preview shows the bounded sample returned by the sanitizer.';
  const isText = activeInputKind === 'text';
  copyButton.hidden = !isText;
  downloadButton.hidden = result.kind === 'disk';
  results.hidden = false;
  resultHeading.focus();
  setStatus(result.kind === 'disk'
    ? 'Sanitization complete. The chosen output file was saved.'
    : 'Sanitization complete.');
}

function renderSegments(target: HTMLElement, segments: Array<{ text: string; changed: boolean }>): void {
  target.replaceChildren();
  for (const segment of segments) {
    if (segment.changed) {
      const mark = document.createElement('mark');
      mark.textContent = segment.text;
      target.append(mark);
    } else {
      target.append(document.createTextNode(segment.text));
    }
  }
}

async function sampleIsBinary(file: File): Promise<boolean> {
  const sample = new Uint8Array(await file.slice(0, 64 * 1024).arrayBuffer());
  return isProbablyBinary(sample);
}

async function chooseDestination(name: string): Promise<WritableFileHandleLike | undefined> {
  if (!showSaveFilePicker) return undefined;
  return showSaveFilePicker({
    suggestedName: name,
    types: [{ description: 'Text file', accept: { 'text/plain': ['.txt', '.log', '.json', '.csv'] } }],
  });
}

function isDataCloneError(reason: unknown): boolean {
  return reason instanceof DOMException && reason.name === 'DataCloneError';
}

function setIdle(): void {
  sanitizeButton.disabled = false;
  cancelButton.hidden = true;
  cancelButton.disabled = false;
  modeControls.forEach((control) => { control.disabled = false; });
  inputControls.forEach((control) => { control.disabled = false; });
  setRuleInputsDisabled(false);
  toggleRulesButton.disabled = false;
  progressWrapper.hidden = true;
}

function setBusy(): void {
  sanitizeButton.disabled = true;
  cancelButton.hidden = false;
  modeControls.forEach((control) => { control.disabled = true; });
  inputControls.forEach((control) => { control.disabled = true; });
  setRuleInputsDisabled(true);
  toggleRulesButton.disabled = true;
  progressWrapper.hidden = false;
  progress.value = 0;
}

function isCurrentPreflight(preflight: ActivePreflight): boolean {
  return activePreflight === preflight;
}

function finishPreflight(preflight: ActivePreflight): boolean {
  if (!isCurrentPreflight(preflight)) return false;
  activePreflight = undefined;
  setIdle();
  return true;
}

function failRun(run: ActiveRun, message: string): void {
  if (!isCurrentRun(run.id, activeRun?.id)) return;
  finishWorker(run);
  clearResult();
  showError(message);
  setStatus('Sanitization could not be completed.');
}

function launchWorker(run: ActiveRun): void {
  let instance: Worker;
  try {
    instance = new Worker(new URL('./sanitize.worker.ts', import.meta.url), { type: 'module' });
  } catch {
    failRun(run, 'Sanitization could not start in this browser.');
    return;
  }
  run.worker = instance;
  instance.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
    if (!isCurrentRun(run.id, activeRun?.id) || run.worker !== instance) return;
    const response = event.data;
    if (response.type === 'progress') {
      const percent = response.totalBytes > 0 ? Math.min(100, response.bytesRead / response.totalBytes * 100) : 0;
      progress.value = percent;
      setStatus(`Sanitizing locally — ${Math.round(percent)}% (${formatBytes(response.bytesRead)} processed).`);
    } else if (response.type === 'complete') {
      if (run.cancelRequested) {
        finishWorker(run);
        clearResult();
        setStatus('Sanitization cancelled.');
        return;
      }
      finishWorker(run);
      renderResult(response.result);
    } else if (response.type === 'cancelled') {
      finishWorker(run);
      clearResult();
      setStatus('Sanitization cancelled.');
    } else if (shouldRetryInMemory(response.code, run.inputBytes) && run.request.destination.kind === 'disk') {
      run.request = { ...run.request, destination: { kind: 'memory' } };
      instance.terminate();
      run.worker = undefined;
      setStatus('Direct-to-disk output was unavailable; retrying with the safe 50 MiB in-memory path.');
      launchWorker(run);
    } else {
      failRun(run, response.code === 'disk-unavailable'
        ? 'Direct-to-disk output is unavailable. Files over 50 MiB cannot be safely processed in memory.'
        : response.message);
    }
  });
  instance.addEventListener('error', () => {
    if (!isCurrentRun(run.id, activeRun?.id) || run.worker !== instance) return;
    failRun(run, 'Sanitization failed. The original input remains available for retry.');
  });
  try {
    instance.postMessage(run.request);
  } catch (reason) {
    if (isDataCloneError(reason) && run.request.destination.kind === 'disk') {
      if (shouldRetryInMemory('disk-unavailable', run.inputBytes)) {
        run.request = { ...run.request, destination: { kind: 'memory' } };
        instance.terminate();
        run.worker = undefined;
        setStatus('Direct-to-disk output was unavailable; retrying with the safe 50 MiB in-memory path.');
        launchWorker(run);
      } else {
        failRun(run, 'Direct-to-disk output is unavailable. Files over 50 MiB cannot be safely processed in memory.');
      }
    } else {
      failRun(run, 'The browser could not start the selected output method. Try again or use a smaller file.');
    }
  }
}

function sendStart(message: StartMessage, inputBytes: number): void {
  const run: ActiveRun = {
    id: ++runSequence,
    request: message,
    inputBytes,
    cancelRequested: false,
  };
  activeRun = run;
  launchWorker(run);
}

function finishWorker(run: ActiveRun): void {
  if (run.cancelTimer !== undefined) window.clearTimeout(run.cancelTimer);
  run.cancelTimer = undefined;
  run.worker?.terminate();
  run.worker = undefined;
  if (isCurrentRun(run.id, activeRun?.id)) activeRun = undefined;
  setIdle();
}

function retireRun(run: ActiveRun): void {
  run.cancelRequested = true;
  activeRun = undefined;
  try {
    run.worker?.postMessage({ type: 'cancel' });
  } catch {
    // The timeout below still terminates a worker that rejects cancellation.
  }
  run.cancelTimer = window.setTimeout(() => {
    run.worker?.terminate();
    run.worker = undefined;
  }, CANCEL_TIMEOUT_MS);
  setIdle();
}

function cancelRun(): void {
  const run = activeRun;
  if (!run || run.cancelRequested) return;
  run.cancelRequested = true;
  cancelButton.disabled = true;
  setStatus('Cancelling…');
  try {
    run.worker?.postMessage({ type: 'cancel' });
  } catch {
    finishWorker(run);
    clearResult();
    setStatus('Sanitization cancelled.');
    return;
  }
  run.cancelTimer = window.setTimeout(() => {
    if (!isCurrentRun(run.id, activeRun?.id)) return;
    finishWorker(run);
    clearResult();
    setStatus('Sanitization cancelled.');
  }, CANCEL_TIMEOUT_MS);
}

async function sanitize(): Promise<void> {
  clearError();
  if (activeRun || activePreflight) return;
  const kind = modeFile.checked ? 'file' : 'text';
  const selected = ruleInputs().filter((input) => input.checked).map((input) => input.value);
  const rules = orderRuleIds(selected);
  if (rules.length === 0) {
    showError('Select at least one sanitization rule.');
    return;
  }
  let input: StartMessage['input'];
  let destination: StartMessage['destination'];
  if (kind === 'file') {
    if (!selectedFile) {
      showError('Choose a file before sanitizing.');
      return;
    }
  }
  const preflight: ActivePreflight = { kind, file: kind === 'file' ? selectedFile : null };
  activePreflight = preflight;
  setBusy();
  let textInputBytes = 0;
  if (kind === 'file') {
    const file = preflight.file!;
    const sizeError = validateInputSize(file.size, 'file', canStreamToDisk());
    if (sizeError) {
      finishPreflight(preflight);
      showError(sizeError);
      return;
    }
    const binaryCheck = sampleIsBinary(file);
    let handle: WritableFileHandleLike | undefined;
    if (canStreamToDisk()) {
      try {
        handle = await chooseDestination(outputFileName(file.name));
      } catch (reason) {
        if (!isCurrentPreflight(preflight)) return;
        finishPreflight(preflight);
        if (reason instanceof DOMException && reason.name === 'AbortError') {
          setStatus('Output selection cancelled.');
          return;
        }
        showError('The browser could not open an output file. Try again or use a smaller file.');
        return;
      }
    }
    if (!isCurrentPreflight(preflight)) return;
    let binary: boolean;
    try {
      binary = await binaryCheck;
    } catch {
      if (!finishPreflight(preflight)) return;
      showError('The browser could not read this file. Try another UTF-8 text file.');
      return;
    }
    if (binary) {
      if (!finishPreflight(preflight)) return;
      showError('This file looks binary. Choose a UTF-8 text file instead.');
      return;
    }
    if (!isCurrentPreflight(preflight)) return;
    if (handle) {
      input = { kind: 'file', blob: file, outputName: outputFileName(file.name) };
      destination = { kind: 'disk', handle };
    } else {
      input = { kind: 'file', blob: file, outputName: outputFileName(file.name) };
      destination = { kind: 'memory' };
    }
  } else {
    if (pasteInput.value === '') {
      finishPreflight(preflight);
      showError('Paste or type text before sanitizing.');
      return;
    }
    const encoded = new TextEncoder().encode(pasteInput.value);
    textInputBytes = encoded.byteLength;
    const sizeError = validateInputSize(textInputBytes, 'text', false);
    if (sizeError) {
      finishPreflight(preflight);
      showError('Pasted text is larger than the 50 MiB limit.');
      return;
    }
    if (isProbablyBinary(encoded.slice(0, 64 * 1024))) {
      finishPreflight(preflight);
      showError('This text contains binary control data. Paste UTF-8 text instead.');
      return;
    }
    input = { kind: 'text', text: pasteInput.value, outputName: 'sanitized.txt' };
    destination = { kind: 'memory' };
  }
  if (!isCurrentPreflight(preflight)) return;
  activeInputKind = kind;
  activeInputBytes = kind === 'file' ? preflight.file!.size : textInputBytes;
  clearResult();
  activePreflight = undefined;
  setStatus('Starting local sanitization…');
  sendStart({ type: 'start', key: session.key, rules, aggressive: aggressive.checked, input, destination }, activeInputBytes);
}

function downloadResult(): void {
  if (!currentResult || currentResult.kind === 'disk') return;
  const blob = currentResult.kind === 'blob' ? currentResult.blob : new Blob([currentResult.text], { type: 'text/plain;charset=utf-8' });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = currentResult.fileName;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(href), 0);
  setStatus('Sanitized result downloaded.');
}

async function copyResult(): Promise<void> {
  if (!currentResult || currentResult.kind !== 'text') return;
  try {
    await navigator.clipboard.writeText(currentResult.text);
    setStatus('Sanitized result copied to the clipboard.');
  } catch {
    showError('Clipboard access was unavailable. Use Download result instead.');
  }
}

function clearSession(): void {
  if (hasResult() && !window.confirm('Discard the current sanitized result?')) return;
  if (activePreflight) {
    activePreflight = undefined;
    setIdle();
  }
  if (activeRun) retireRun(activeRun);
  selectedFile = null;
  fileInput.value = '';
  pasteInput.value = '';
  pasteValue = '';
  fileName.textContent = '';
  aggressive.checked = false;
  ruleInputs().forEach((input) => { input.checked = true; });
  updateToggleLabel();
  modeFile.checked = true;
  updateMode();
  activeInputBytes = 0;
  clearResult();
  clearError();
  session = replaceSessionKey(storage);
  setStatus('Session cleared. A new replacement key is active.');
}

function switchMode(next: 'file' | 'text'): void {
  const previous = next === 'file' ? modeText : modeFile;
  if (activePreflight) {
    previous.checked = true;
    updateMode();
    return;
  }
  if (!allowInputTransition(() => {
    previous.checked = true;
    updateMode();
  })) return;
  if (next === 'file') {
    pasteInput.value = '';
    pasteValue = '';
    activeInputKind = 'file';
  } else {
    selectedFile = null;
    fileInput.value = '';
    fileName.textContent = '';
    activeInputKind = 'text';
  }
  updateMode();
}

modeFile.addEventListener('change', () => switchMode('file'));
modeText.addEventListener('change', () => switchMode('text'));
fileInput.addEventListener('change', () => setFile(fileInput.files?.[0]));
pasteInput.addEventListener('input', () => {
  if (activePreflight) {
    pasteInput.value = pasteValue;
    return;
  }
  if (!allowInputTransition(() => { pasteInput.value = pasteValue; })) return;
  pasteValue = pasteInput.value;
  if (pasteInput.value) {
    selectedFile = null;
    fileInput.value = '';
    fileName.textContent = '';
  }
});
dropZone.addEventListener('dragover', (event) => { event.preventDefault(); dropZone.classList.add('dragging'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
dropZone.addEventListener('drop', (event) => {
  event.preventDefault();
  dropZone.classList.remove('dragging');
  setFile(event.dataTransfer?.files[0]);
});
toggleRulesButton.addEventListener('click', () => {
  const select = toggleRulesButton.textContent === 'Select all';
  ruleInputs().forEach((input) => { input.checked = select; });
  updateToggleLabel();
});
sanitizeButton.addEventListener('click', () => { void sanitize(); });
cancelButton.addEventListener('click', cancelRun);
copyButton.addEventListener('click', () => { void copyResult(); });
downloadButton.addEventListener('click', downloadResult);
clearSessionButton.addEventListener('click', clearSession);

renderRules();
updateMode();
updateLimitText();
if (!session.persisted) $('privacy-status').textContent = 'Processed entirely in this browser (refresh changes tokens)';
