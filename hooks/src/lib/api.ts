/**
 * Raidu API integration: token reader and remote validation.
 *
 * Security:
 * - Token read from ~/.raidu/token (0600 perms), NOT from settings.json
 * - No shell commands (uses execFileSync with array args)
 * - Token never appears in process list as part of a shell string
 * - Input capped to prevent sending huge payloads
 */

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { debug } from './audit';
import type { BlockReport, EvidenceVerdict } from './types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const API_BASE = process.env.RAIDU_API_BASE || 'https://sandbox.raidu.com';
const TOKEN_FILE = path.join(os.homedir(), '.raidu', 'token');
const MAX_API_INPUT = 100_000;
/** Tower's IdeValidateResponseDto cap. */
const MAX_RESPONSE_INPUT = 200_000;

// ---------------------------------------------------------------------------
// Token reader (secure file, not settings.json)
// ---------------------------------------------------------------------------

export function hasToken(): boolean {
  return getToken() !== null;
}

function getToken(): string | null {
  try {
    const token = fs.readFileSync(TOKEN_FILE, 'utf-8').trim();
    return token || null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Settings reader (for non-secret values like workspaceId, environmentId)
// ---------------------------------------------------------------------------

function getSettingsDir(): string | null {
  switch (process.platform) {
    case 'darwin':
      return path.join(os.homedir(), 'Library', 'Application Support', 'Cursor', 'User');
    case 'linux':
      return path.join(os.homedir(), '.config', 'Cursor', 'User');
    case 'win32':
      return path.join(process.env.APPDATA || '', 'Cursor', 'User');
    default:
      return null;
  }
}

export function readSetting(key: string): string | null {
  try {
    const dir = getSettingsDir();
    if (!dir) return null;
    const p = path.join(dir, 'settings.json');
    return JSON.parse(fs.readFileSync(p, 'utf-8'))[key] || null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// API validation
// ---------------------------------------------------------------------------

export interface APIValidationResult {
  passed: boolean;
  entities?: Array<{ type: string; start?: number; end?: number; confidence?: number }>;
  sanitizedInput?: string;
  summary?: { pii?: number; pci?: number; phi?: number; secrets?: number };
  processingTimeMs?: number;
  /** Whether Tower stored the violation row (newer servers only). */
  evidence?: EvidenceVerdict;
}

export function validateViaAPI(input: string, fileContent?: string[]): APIValidationResult | null {
  const token = getToken();
  if (!token) {
    debug('API: no token, skipping');
    return null;
  }

  const safeInput = input.slice(0, MAX_API_INPUT);
  const envId = readSetting('raidu.environmentId');

  // Tower scans input + fileContent together (joined by '\n'); keep the
  // combined size within the same cap as a prompt alone.
  let budget = MAX_API_INPUT - safeInput.length;
  const files: string[] = [];
  for (const f of fileContent ?? []) {
    if (budget <= 1) break;
    const part = f.slice(0, budget - 1);
    files.push(part);
    budget -= part.length + 1;
  }
  const body = JSON.stringify(files.length > 0 ? { input: safeInput, fileContent: files } : { input: safeInput });
  const url = `${API_BASE}/api/guardrails/ide/validate`;
  const startMs = performance.now();

  debug(`API: POST ${url} (${body.length}B, env=${envId || 'none'})`);

  try {
    const result = execFileSync(
      'curl',
      [
        '-fsSL',
        '-X',
        'POST',
        '-H',
        `Authorization: Bearer ${token}`,
        '-H',
        'Content-Type: application/json',
        '--data-binary',
        '@-',
        url,
      ],
      // Body over stdin, not argv: keeps prompt and file content out of the process list.
      { input: body, timeout: 8000, encoding: 'utf-8' as BufferEncoding, stdio: ['pipe', 'pipe', 'pipe'] },
    );

    const latencyMs = (performance.now() - startMs).toFixed(0);
    const parsed = JSON.parse(result as string);

    debug(
      `API: ${latencyMs}ms | passed=${parsed.passed} | entities=${parsed.entities?.length || 0} | sanitized=${!!parsed.sanitizedInput} | serverMs=${parsed.processingTimeMs || '?'}`,
    );

    return parsed;
  } catch (err: unknown) {
    const latencyMs = (performance.now() - startMs).toFixed(0);
    debug(`API: FAILED after ${latencyMs}ms | ${(err as Error).message?.slice(0, 150)}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Block reports (called from the detached flusher, never from a hook directly)
// ---------------------------------------------------------------------------

/**
 * POST a batch of block reports. Returns per-report verdicts in request order,
 * or null on any failure (no token, network, non-2xx), so the caller requeues.
 */
export function postBlockReports(reports: BlockReport[]): EvidenceVerdict[] | null {
  const token = getToken();
  if (!token || reports.length === 0) return null;

  const url = `${API_BASE}/api/guardrails/ide/report`;
  const body = JSON.stringify({ reports });

  try {
    const result = execFileSync(
      'curl',
      [
        '-fsSL',
        '-X',
        'POST',
        '-H',
        `Authorization: Bearer ${token}`,
        '-H',
        'Content-Type: application/json',
        '--data-binary',
        '@-',
        url,
      ],
      // Body over stdin, not argv: keeps it out of the process list.
      { input: body, timeout: 15000, encoding: 'utf-8' as BufferEncoding, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    const parsed = JSON.parse(result as string) as { results?: EvidenceVerdict[] };
    if (!Array.isArray(parsed.results)) return null;
    return parsed.results;
  } catch (err: unknown) {
    debug(`API: report FAILED | ${(err as Error).message?.slice(0, 150)}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Response scan (called from the detached response scanner, never from a hook)
// ---------------------------------------------------------------------------

export interface ResponseScanRequest {
  response: string;
  prompt?: string;
  ideConversationId?: string;
  ideGenerationId?: string;
}

/**
 * POST a model reply to /api/guardrails/ide/validate-response. Tower scans it
 * against the configured security policies and records the violation itself.
 * Returns false on any failure.
 */
export function postResponseScan(req: ResponseScanRequest): boolean {
  const token = getToken();
  if (!token || !req.response) return false;

  const url = `${API_BASE}/api/guardrails/ide/validate-response`;
  const body = JSON.stringify({
    response: req.response.slice(0, MAX_RESPONSE_INPUT),
    prompt: req.prompt?.slice(0, MAX_RESPONSE_INPUT),
    ideConversationId: req.ideConversationId?.slice(0, 100),
    ideGenerationId: req.ideGenerationId?.slice(0, 100),
  });

  try {
    const result = execFileSync(
      'curl',
      [
        '-fsSL',
        '-X',
        'POST',
        '-H',
        `Authorization: Bearer ${token}`,
        '-H',
        'Content-Type: application/json',
        '--data-binary',
        '@-',
        url,
      ],
      { input: body, timeout: 30000, encoding: 'utf-8' as BufferEncoding, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    const parsed = JSON.parse(result as string) as { passed?: boolean; action?: string; violations?: unknown[] };
    debug(
      `API: response scan passed=${parsed.passed} action=${parsed.action} violations=${parsed.violations?.length ?? 0}`,
    );
    return true;
  } catch (err: unknown) {
    debug(`API: response scan FAILED | ${(err as Error).message?.slice(0, 150)}`);
    return false;
  }
}

// ---------------------------------------------------------------------------
// Image scan
// ---------------------------------------------------------------------------

/**
 * POST an image attached to a prompt to /api/guardrails/ide/validate-image,
 * where Tower's Presidio image redactor looks for sensitive text in it and
 * records the violation. Returns null on any failure (no token, older server,
 * redactor down), so the caller can treat the image as unscanned.
 */
export function validateImageViaAPI(
  base64: string,
  meta: { fileName?: string; ideConversationId?: string; ideGenerationId?: string },
): { passed: boolean } | null {
  const token = getToken();
  if (!token) return null;

  const url = `${API_BASE}/api/guardrails/ide/validate-image`;
  const body = JSON.stringify({
    image: base64,
    fileName: meta.fileName?.slice(0, 255),
    ideConversationId: meta.ideConversationId?.slice(0, 100),
    ideGenerationId: meta.ideGenerationId?.slice(0, 100),
  });
  const startMs = performance.now();

  try {
    const result = execFileSync(
      'curl',
      [
        '-fsSL',
        '-X',
        'POST',
        '-H',
        `Authorization: Bearer ${token}`,
        '-H',
        'Content-Type: application/json',
        '--data-binary',
        '@-',
        url,
      ],
      // Image OCR is slower than a text scan; beforeSubmitPrompt allows 30s.
      {
        input: body,
        timeout: 20000,
        encoding: 'utf-8' as BufferEncoding,
        stdio: ['pipe', 'pipe', 'pipe'],
        maxBuffer: 1_000_000,
      },
    );
    const parsed = JSON.parse(result as string) as { passed?: boolean };
    debug(`API: image scan ${(performance.now() - startMs).toFixed(0)}ms | passed=${parsed.passed}`);
    return typeof parsed.passed === 'boolean' ? { passed: parsed.passed } : null;
  } catch (err: unknown) {
    debug(
      `API: image scan FAILED after ${(performance.now() - startMs).toFixed(0)}ms | ${(err as Error).message?.slice(0, 150)}`,
    );
    return null;
  }
}
