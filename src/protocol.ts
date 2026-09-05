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
