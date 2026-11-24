/**
 * Handler: beforeSubmitPrompt
 *
 * Scans the prompt AND the files attached to it. Cursor sends a file the user
 * @-mentions, pastes from the editor (shown as `.env(1-8)`) or uploads as an
 * attachment path; the prompt text alone does not contain it, so scanning only
 * the text let `.env` content and uploaded credentials reach the model
 * (RAI-4807 #8, #10).
 */

import * as path from 'node:path';
import { audit, incStat } from '../lib/audit';
import { findBlockedValues, rememberBlockedValues, rememberSecretsIn } from '../lib/blocked-values';
import { readTextForScan } from '../lib/content';
import { allow, denyPrompt, ids } from '../lib/helpers';
import { classifySensitiveFile } from '../lib/policy';
import {
  copyToClipboard,
  entitySummary,
  formatEntities,
  redactText,
  type ScanFile,
  scanTextWithFiles,
} from '../lib/redaction';
import { reportBlock, reportScanBlockIfUnrecorded } from '../lib/report';
import type { HookEvent, HookResponse } from '../lib/types';

/** Attachments read per prompt, and bytes per attachment. */
const MAX_ATTACHMENTS = 20;
const MAX_ATTACHMENT_BYTES = 500_000;

const NEW_CHAT_HINT = 'Start a new chat so the blocked value is not reused from this conversation.';

export function handleBeforeSubmitPrompt(event: HookEvent): HookResponse {
  const prompt = event.prompt || '';
  const attachments = (event.attachments || [])
    .filter((a) => a?.type !== 'rule' && typeof a?.file_path === 'string' && a.file_path)
    .slice(0, MAX_ATTACHMENTS);
  if (!prompt && attachments.length === 0) return allow();
  incStat('totalScans');

  // 1. An attached file that is sensitive by name (.env, keys) is blocked the
  //    same way reading it would be: attaching it sends its content.
  const files: ScanFile[] = [];
  const unscanned: string[] = [];
  for (const a of attachments) {
    const filePath = a.file_path as string;
    const fileName = path.basename(filePath);
    const hit = classifySensitiveFile(filePath);
    if (hit?.mode === 'block') {
      incStat('promptsBlocked');
      audit({ event: 'beforeSubmitPrompt', action: 'blocked', filePath, reason: hit.rule, ...ids(event) });
      reportBlock(event, {
        event: 'beforeSubmitPrompt',
        kind: 'sensitive_file',
        detector: 'local',
        rule: hit.rule,
        fileName,
      });
      // Remember what is in it, so the agent cannot pull it in another way.
      const read = readTextForScan(filePath, MAX_ATTACHMENT_BYTES);
      if (read.ok) rememberSecretsIn(read.text);
      return denyPrompt(`${fileName} is a protected file (policy: ${hit.rule}) and cannot be sent to the model.`);
    }
    const read = readTextForScan(filePath, MAX_ATTACHMENT_BYTES);
    if (read.ok) files.push({ label: fileName, text: read.text });
    else if (read.reason === 'binary') unscanned.push(fileName);
  }

  // 2. Scan the prompt and the attached content together.
  const result = scanTextWithFiles(prompt, files);

  if (result.entities.length > 0) {
    incStat('piiFound', result.entities.length);
    incStat('promptsBlocked');
    rememberBlockedValues(result.entities);

    const attachmentsHit = result.foundIn.filter((f) => f !== 'prompt');
    const promptHit = result.foundIn.includes('prompt');

    // Only the prompt goes to the clipboard, never attached file content.
    let clipboardNote = '';
    if (promptHit) {
      const promptEntities = result.entities.filter((e) => e.end <= prompt.length && e.start !== e.end);
      const safeVersion = redactText(prompt, promptEntities);
      if (safeVersion !== prompt) {
        copyToClipboard(safeVersion);
        clipboardNote = ' A compliant version of your prompt is in your clipboard. Press Cmd+V.';
      }
    }

    audit({
      event: 'beforeSubmitPrompt',
      action: 'blocked',
      source: result.source,
      entities: entitySummary(result.entities),
      attachments: attachmentsHit.length > 0 ? attachmentsHit : undefined,
      scanTimeMs: result.scanTimeMs,
      ...ids(event),
    });
    reportScanBlockIfUnrecorded(event, result, { event: 'beforeSubmitPrompt' });

    const where =
      attachmentsHit.length > 0 ? `${promptHit ? 'your prompt and ' : ''}${attachmentsHit.join(', ')}` : 'your prompt';
    return denyPrompt(`Detected ${formatEntities(result.entities)} in ${where}.${clipboardNote} ${NEW_CHAT_HINT}`);
  }

  // 3. A value blocked earlier must not come back in a later prompt either.
  const reused = findBlockedValues([prompt, ...files.map((f) => f.text)].join('\n'));
  if (reused.length > 0) {
    incStat('promptsBlocked');
    audit({
      event: 'beforeSubmitPrompt',
      action: 'blocked',
      reason: 'previously_blocked_value',
      entities: reused.map((type) => ({ type, score: 1 })),
      ...ids(event),
    });
    reportBlock(event, {
      event: 'beforeSubmitPrompt',
      kind: 'sensitive_data',
      detector: 'local',
      entityTypes: reused,
      rule: 'previously_blocked_value',
    });
    return denyPrompt(
      `This prompt contains a value Raidu Firewall blocked earlier (${reused.join(', ')}). ${NEW_CHAT_HINT}`,
    );
  }

  audit({
    event: 'beforeSubmitPrompt',
    action: 'allowed',
    source: result.source,
    scanTimeMs: result.scanTimeMs,
    attachments: files.length > 0 ? files.map((f) => f.label) : undefined,
    unscanned: unscanned.length > 0 ? unscanned : undefined,
    ...ids(event),
  });
  return allow();
}
