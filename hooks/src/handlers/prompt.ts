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
import { audit, debug, incStat } from '../lib/audit';
import {
  blockedConversation,
  markConversationBlocked,
  matchBlockedValues,
  rememberBlockedValues,
  rememberSecretsIn,
} from '../lib/blocked-values';
import { isImagePath, readTextForScan } from '../lib/content';
import { allow, denyPrompt, ids } from '../lib/helpers';
import { scanImageFile } from '../lib/image-scan';
import { classifySensitiveFile } from '../lib/policy';
import {
  copyToClipboard,
  entitySummary,
  formatEntities,
  redactText,
  type ScanFile,
  scanTextLocal,
  scanTextWithFiles,
} from '../lib/redaction';
import { reportBlock, reportScanBlockIfUnrecorded } from '../lib/report';
import type { HookEvent, HookResponse } from '../lib/types';

/** Attachments read per prompt, and bytes per attachment. */
const MAX_ATTACHMENTS = 20;
const MAX_ATTACHMENT_BYTES = 500_000;
/** Images sent to Tower's image scan per prompt (each one is an OCR pass). */
const MAX_IMAGES = 3;

const NEW_CHAT_HINT =
  'Edit that message to take the sensitive data out, or start a new chat: until then further prompts in this chat are blocked.';
/** A blocked file or image cannot be seen leaving the chat, so only a new chat clears it. */
const NEW_CHAT_ONLY_HINT =
  'Start a new chat: this one now holds the blocked content, and further prompts here are blocked.';

export function handleBeforeSubmitPrompt(event: HookEvent): HookResponse {
  const prompt = event.prompt || '';
  const attachments = (event.attachments || [])
    .filter((a) => a?.type !== 'rule' && typeof a?.file_path === 'string' && a.file_path)
    .slice(0, MAX_ATTACHMENTS);
  if (!prompt && attachments.length === 0) return allow();
  incStat('totalScans');

  // TEMP RAI-4807 probe: which fields Cursor sends with a prompt (names only).
  debug(`beforeSubmitPrompt payload keys: ${Object.keys(event).sort().join(',')}`);

  // 0. Cursor keeps a blocked prompt in the chat and sends it as history with
  //    every later prompt, so the model still sees the blocked data. A hook
  //    cannot edit that history: block the conversation while the blocked
  //    message is still in it (read from the transcript when Cursor gives one).
  const held = blockedConversation(event.conversation_id, event.transcript_path);
  if (held.check) debug(`conversation held check: ${held.check}`);
  if (held.check === 'cleared') {
    audit({ event: 'beforeSubmitPrompt', action: 'unblocked', reason: 'blocked_message_removed', ...ids(event) });
  }
  const heldTypes = held.types;
  if (heldTypes) {
    incStat('promptsBlocked');
    // Not sent anywhere, but remember what it carries so the values stay blocked.
    rememberBlockedValues(scanTextLocal(prompt).entities);
    audit({
      event: 'beforeSubmitPrompt',
      action: 'blocked',
      reason: 'conversation_holds_blocked_prompt',
      check: held.check,
      ...ids(event),
    });
    reportBlock(event, {
      event: 'beforeSubmitPrompt',
      kind: 'sensitive_data',
      detector: 'local',
      entityTypes: heldTypes,
      rule: 'conversation_holds_blocked_prompt',
    });
    if (heldTypes.includes('IMAGE_SENSITIVE_DATA')) {
      return denyPrompt(
        'This chat contains an image with sensitive data, and Cursor would send it to the model again with this prompt. Start a new chat to continue.',
      );
    }
    return denyPrompt(
      held.check === 'not_values'
        ? 'This chat still contains content Raidu Firewall blocked, and Cursor would send it to the model again with this prompt. Start a new chat to continue.'
        : 'This chat still contains a message Raidu Firewall blocked, and Cursor would send it to the model again with this prompt. Edit that message to take the sensitive data out, or start a new chat.',
    );
  }

  // 1. An attached file that is sensitive by name (.env, keys) is blocked the
  //    same way reading it would be: attaching it sends its content.
  const files: ScanFile[] = [];
  const unscanned: string[] = [];
  const images: Array<{ filePath: string; fileName: string }> = [];
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
      markConversationBlocked(event.conversation_id, ['SENSITIVE_FILE']);
      return denyPrompt(
        `${fileName} is a protected file (policy: ${hit.rule}) and cannot be sent to the model. ${NEW_CHAT_ONLY_HINT}`,
      );
    }
    if (isImagePath(filePath)) {
      images.push({ filePath, fileName });
      continue;
    }
    const read = readTextForScan(filePath, MAX_ATTACHMENT_BYTES);
    if (read.ok) files.push({ label: fileName, text: read.text });
    else if (read.reason === 'binary') unscanned.push(fileName);
  }

  // 1b. Images: the text scanners cannot read them. Tower's Presidio image
  //     redactor finds text (emails, SSNs, keys) in screenshots and uploads,
  //     and records the violation itself (RAI-4807 #10).
  for (const [i, img] of images.entries()) {
    const verdict =
      i < MAX_IMAGES
        ? scanImageFile(img.filePath, {
            ideConversationId: event.conversation_id,
            ideGenerationId: event.generation_id,
          })
        : 'unscanned';
    if (verdict === 'unscanned') {
      unscanned.push(img.fileName);
      continue;
    }
    if (verdict === 'found') {
      incStat('promptsBlocked');
      markConversationBlocked(event.conversation_id, ['IMAGE_SENSITIVE_DATA']);
      audit({
        event: 'beforeSubmitPrompt',
        action: 'blocked',
        reason: 'sensitive_data_in_image',
        attachments: [img.fileName],
        ...ids(event),
      });
      // Tower already recorded the violation for this image; nothing to report.
      return denyPrompt(
        `Detected sensitive data in the image ${img.fileName}. Remove it or redact it before sending. ${NEW_CHAT_ONLY_HINT}`,
      );
    }
  }

  // 2. Scan the prompt and the attached content together.
  const result = scanTextWithFiles(prompt, files);

  if (result.entities.length > 0) {
    incStat('piiFound', result.entities.length);
    incStat('promptsBlocked');
    rememberBlockedValues(result.entities);

    const attachmentsHit = result.foundIn.filter((f) => f !== 'prompt');
    const promptHit = result.foundIn.includes('prompt');
    // Values are passed only when the prompt text alone was blocked: an attached
    // file's content may not show in the transcript, so its absence proves nothing.
    markConversationBlocked(
      event.conversation_id,
      result.entities.map((e) => e.type),
      attachmentsHit.length === 0 ? result.entities.map((e) => e.value) : undefined,
    );

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
    return denyPrompt(
      `Detected ${formatEntities(result.entities)} in ${where}.${clipboardNote} ${attachmentsHit.length === 0 ? NEW_CHAT_HINT : NEW_CHAT_ONLY_HINT}`,
    );
  }

  // 3. A value blocked earlier must not come back in a later prompt either.
  const promptReused = matchBlockedValues(prompt);
  const fileReused = files.length > 0 ? matchBlockedValues(files.map((f) => f.text).join('\n')) : [];
  const reused = [...new Set([...promptReused, ...fileReused].map((m) => m.type))];
  if (reused.length > 0) {
    incStat('promptsBlocked');
    markConversationBlocked(
      event.conversation_id,
      reused,
      fileReused.length === 0 ? promptReused.map((m) => m.value) : undefined,
    );
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
      `This prompt contains a value Raidu Firewall blocked earlier (${reused.join(', ')}). ${fileReused.length === 0 ? NEW_CHAT_HINT : NEW_CHAT_ONLY_HINT}`,
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
