import { RULES, getInputLimit, getOrCreateSessionKey, isProbablyBinary, limitPreviewSegments, orderRuleIds, outputFileName, replaceSessionKey, validateInputSize, type InputKind, type SessionKeyState } from './policy';
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
const modeControls = [modeFile, modeText];
const inputControls = [fileInput, pasteInput, aggressive];

let selectedFile: File | null = null;
let session: SessionKeyState;
let worker: Worker | undefined;
let currentResult: CompleteResult | undefined;
let activeInputKind: InputKind | undefined;
let cancelTimer: number | undefined;

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
  return typeof (window as PickerWindow).showSaveFilePicker === 'function';
}

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

function confirmReplacingResult(): boolean {
  return !hasResult() || window.confirm('Replace the current sanitized result? It has not been exported yet.');
}

function setFile(file: File | undefined): void {
  if (!file) return;
  selectedFile = file;
  pasteInput.value = '';
  fileName.textContent = `${file.name} (${formatBytes(file.size)}). Suggested output: ${outputFileName(file.name)} — keep the output name distinct from the source.`;
  clearResult();
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

function renderResult(result: CompleteResult): void {
  currentResult = result;
  const report = result.report;
  totalMatches.textContent = String(report.totalMatches);
  lineCount.textContent = String(report.lineCount);
  countsList.replaceChildren(...Object.entries(report.counts).map(([id, count]) => {
    const item = document.createElement('li');
    item.textContent = `${RULES.find((rule) => rule.id === id)?.label ?? id}: ${count}`;
    return item;
  }));
  const beforeLimited = limitPreviewSegments(report.preview.before);
  const afterLimited = limitPreviewSegments(report.preview.after);
  renderSegments(beforePreview, beforeLimited.segments);
  renderSegments(afterPreview, afterLimited.segments);
  previewNote.textContent = beforeLimited.truncated || afterLimited.truncated
    ? 'Preview limited to the first 200 lines.'
    : 'Preview shows the bounded sample returned by the sanitizer.';
  const isText = activeInputKind === 'text';
  copyButton.hidden = !isText;
  downloadButton.hidden = result.kind === 'disk';
  results.hidden = false;
  resultHeading.focus();
  setStatus('Sanitization complete.');
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
  const sample = new Uint8Array(await file.slice(0, 8192).arrayBuffer());
  return isProbablyBinary(sample);
}

async function chooseDestination(name: string): Promise<WritableFileHandleLike | undefined> {
  const picker = (window as PickerWindow).showSaveFilePicker;
  if (!picker) return undefined;
  return picker({
    suggestedName: name,
    types: [{ description: 'Text file', accept: { 'text/plain': ['.txt', '.log', '.json', '.csv'] } }],
  });
}

function sendStart(message: StartMessage): void {
  const instance = new Worker(new URL('./sanitize.worker.ts', import.meta.url), { type: 'module' });
  worker = instance;
  instance.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
    if (worker !== instance) return;
    const response = event.data;
    if (response.type === 'progress') {
      const percent = response.totalBytes > 0 ? Math.min(100, response.bytesRead / response.totalBytes * 100) : 0;
      progress.value = percent;
      setStatus(`Sanitizing locally — ${Math.round(percent)}% (${formatBytes(response.bytesRead)} processed).`);
    } else if (response.type === 'complete') {
      finishWorker(instance);
      renderResult(response.result);
    } else if (response.type === 'cancelled') {
      finishWorker(instance);
      clearResult();
      setStatus('Sanitization cancelled.');
    } else {
      finishWorker(instance);
      clearResult();
      showError(response.message);
      setStatus('Sanitization could not be completed.');
    }
  });
  instance.addEventListener('error', () => {
    if (worker !== instance) return;
    finishWorker(instance);
    showError('Sanitization failed. The original input remains available for retry.');
  });
  instance.postMessage(message);
}

function finishWorker(instance: Worker): void {
  if (cancelTimer !== undefined) window.clearTimeout(cancelTimer);
  cancelTimer = undefined;
  instance.terminate();
  if (worker === instance) worker = undefined;
  sanitizeButton.disabled = false;
  cancelButton.hidden = true;
  modeControls.forEach((control) => { control.disabled = false; });
  inputControls.forEach((control) => { control.disabled = false; });
  toggleRulesButton.disabled = false;
  progressWrapper.hidden = true;
}

function cancelRun(): void {
  if (!worker) return;
  cancelButton.disabled = true;
  worker.postMessage({ type: 'cancel' });
  cancelTimer = window.setTimeout(() => {
    if (!worker) return;
    const instance = worker;
    finishWorker(instance);
    clearResult();
    setStatus('Sanitization cancelled.');
  }, 2000);
}

async function sanitize(): Promise<void> {
  clearError();
  if (worker) return;
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
    const sizeError = validateInputSize(selectedFile.size, 'file', canStreamToDisk());
    if (sizeError) {
      showError(sizeError);
      return;
    }
    if (await sampleIsBinary(selectedFile)) {
      showError('This file looks binary. Choose a UTF-8 text file instead.');
      return;
    }
    let handle: WritableFileHandleLike | undefined;
    if (canStreamToDisk()) {
      try {
        handle = await chooseDestination(outputFileName(selectedFile.name));
      } catch (reason) {
        if (reason instanceof DOMException && reason.name === 'AbortError') {
          setStatus('Output selection cancelled.');
          return;
        }
        showError('The browser could not open an output file. Try again or use a smaller file.');
        return;
      }
    }
    if (handle) {
      input = { kind: 'file', blob: selectedFile, outputName: outputFileName(selectedFile.name) };
      destination = { kind: 'disk', handle };
    } else {
      input = { kind: 'file', blob: selectedFile, outputName: outputFileName(selectedFile.name) };
      destination = { kind: 'memory' };
    }
  } else {
    const bytes = new TextEncoder().encode(pasteInput.value).byteLength;
    const sizeError = validateInputSize(bytes, 'text', false);
    if (sizeError) {
      showError('Pasted text is larger than the 50 MiB limit.');
      return;
    }
    if (isProbablyBinary(new TextEncoder().encode(pasteInput.value.slice(0, 8192)))) {
      showError('This text contains binary control data. Paste UTF-8 text instead.');
      return;
    }
    input = { kind: 'text', text: pasteInput.value, outputName: 'sanitized.txt' };
    destination = { kind: 'memory' };
  }
  activeInputKind = kind;
  clearResult();
  sanitizeButton.disabled = true;
  cancelButton.hidden = false;
  modeControls.forEach((control) => { control.disabled = true; });
  inputControls.forEach((control) => { control.disabled = true; });
  toggleRulesButton.disabled = true;
  progressWrapper.hidden = false;
  progress.value = 0;
  setStatus('Starting local sanitization…');
  sendStart({ type: 'start', key: session.key, rules, aggressive: aggressive.checked, input, destination });
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
  if (worker) cancelRun();
  selectedFile = null;
  fileInput.value = '';
  pasteInput.value = '';
  fileName.textContent = '';
  aggressive.checked = false;
  ruleInputs().forEach((input) => { input.checked = true; });
  updateToggleLabel();
  modeFile.checked = true;
  updateMode();
  clearResult();
  clearError();
  session = replaceSessionKey(storage);
  setStatus('Session cleared. A new replacement key is active.');
}

function switchMode(next: 'file' | 'text'): void {
  if (!confirmReplacingResult()) {
    if (next === 'file') modeText.checked = true;
    else modeFile.checked = true;
    return;
  }
  clearResult();
  if (next === 'file') {
    pasteInput.value = '';
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
  if (pasteInput.value) {
    selectedFile = null;
    fileInput.value = '';
    fileName.textContent = '';
    clearResult();
  }
});
dropZone.addEventListener('dragover', (event) => { event.preventDefault(); dropZone.classList.add('dragging'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
dropZone.addEventListener('drop', (event) => {
  event.preventDefault();
  dropZone.classList.remove('dragging');
  if (confirmReplacingResult()) setFile(event.dataTransfer?.files[0]);
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
