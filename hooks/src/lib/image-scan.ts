/**
 * Images: sensitive text in screenshots and uploads (RAI-4807 #10).
 *
 * The text scanners cannot read an image. Tower's /validate-image runs the
 * Presidio image redactor on it and records the violation itself.
 *
 * Where images show up: Cursor does NOT pass an uploaded or pasted chat image
 * to beforeSubmitPrompt. It saves it into the workspace as image-<uuid>.png
 * and the agent then opens it with the Read tool, so the same image reaches
 * preToolUse (Read) and beforeReadFile. Each of those, and prompt attachments,
 * calls scanImageFile.
 *
 * The verdict is cached per image content (SHA-256) for a few minutes, so the
 * two hooks of one read cost one OCR pass and write one Tower violation.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { validateImageViaAPI } from './api';
import { audit, debug, incStat, LOG_DIR } from './audit';
import { markConversationBlocked } from './blocked-values';
import { MAX_IMAGE_BYTES } from './content';
import { deny, ids } from './helpers';
import type { HookEvent, HookResponse } from './types';

const CACHE_FILE = path.join(LOG_DIR, 'image-verdicts.json');
const CACHE_TTL_MS = 10 * 60_000;
const MAX_CACHE_ENTRIES = 200;

export type ImageVerdict = 'found' | 'clean' | 'unscanned';

interface CachedVerdict {
  v: 'found' | 'clean';
  at: number;
}

function loadCache(): Record<string, CachedVerdict> {
  try {
    const all = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf-8')) as Record<string, CachedVerdict>;
    const cutoff = Date.now() - CACHE_TTL_MS;
    return Object.fromEntries(Object.entries(all).filter(([, e]) => e && e.at > cutoff));
  } catch {
    return {};
  }
}

function saveVerdict(hash: string, v: 'found' | 'clean'): void {
  try {
    const all = loadCache();
    all[hash] = { v, at: Date.now() };
    const kept = Object.entries(all)
      .sort((a, b) => a[1].at - b[1].at)
      .slice(-MAX_CACHE_ENTRIES);
    fs.writeFileSync(CACHE_FILE, JSON.stringify(Object.fromEntries(kept)), { mode: 0o600 });
  } catch {}
}

/**
 * Scan an image file. 'unscanned' when it cannot be read, is too large, there
 * is no token, or Tower cannot scan it (older server, redactor down): the
 * caller allows it and audits it as unscanned, as for any file it cannot read.
 */
export function scanImageFile(
  filePath: string,
  meta: { ideConversationId?: string; ideGenerationId?: string },
): ImageVerdict {
  let data: Buffer;
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size === 0 || st.size > MAX_IMAGE_BYTES) return 'unscanned';
    data = fs.readFileSync(filePath);
  } catch {
    return 'unscanned';
  }

  const hash = crypto.createHash('sha256').update(data).digest('hex');
  const cached = loadCache()[hash];
  if (cached) {
    debug(`image scan: cached ${cached.v}`);
    return cached.v;
  }

  const verdict = validateImageViaAPI(data.toString('base64'), {
    fileName: path.basename(filePath),
    ...meta,
  });
  if (!verdict) return 'unscanned';
  const v = verdict.passed ? 'clean' : 'found';
  saveVerdict(hash, v);
  return v;
}

/** Resolve a tool's file path the way the agent does: relative to its cwd or the workspace. */
export function resolveToolPath(filePath: string, cwd?: string, roots?: string[]): string {
  if (path.isAbsolute(filePath)) return filePath;
  for (const base of [cwd, ...(roots ?? []), process.env.CURSOR_PROJECT_DIR].filter(Boolean) as string[]) {
    const p = path.resolve(base, filePath);
    if (fs.existsSync(p)) return p;
  }
  return path.resolve(filePath);
}

/** An image the agent is about to read: Tower's image scan decides (RAI-4807 #10). */
export function blockImageRead(
  event: HookEvent,
  hookEvent: 'beforeReadFile' | 'preToolUse',
  filePath: string,
): HookResponse | null {
  const verdict = scanImageFile(filePath, {
    ideConversationId: event.conversation_id,
    ideGenerationId: event.generation_id,
  });
  if (verdict !== 'found') {
    if (verdict === 'unscanned')
      audit({ event: hookEvent, action: 'allowed', filePath, inspected: 'unscanned', ...ids(event) });
    return null;
  }
  incStat('commandsBlocked');
  // The image came with the user's message: that conversation now holds it.
  markConversationBlocked(event.conversation_id, ['IMAGE_SENSITIVE_DATA']);
  audit({ event: hookEvent, action: 'blocked', filePath, reason: 'sensitive_data_in_image', ...ids(event) });
  // Tower recorded the violation when it scanned the image; nothing to report.
  return deny(
    `Blocked reading the image ${path.basename(filePath)}: it contains sensitive data. Remove or redact it, and start a new chat.`,
  );
}
