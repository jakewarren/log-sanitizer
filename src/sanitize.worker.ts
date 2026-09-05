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
