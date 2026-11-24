/**
 * Handler: afterFileEdit
 */

import { audit, incStat } from '../lib/audit';
import { isImagePath } from '../lib/content';
import { allow, ids } from '../lib/helpers';
import { scanSavedImageInBackground } from '../lib/image-scan';
import { entitySummary, MAX_SCAN_SIZE, scanTextLocal } from '../lib/redaction';
import type { HookEvent, HookResponse } from '../lib/types';

export function handleAfterFileEdit(event: HookEvent): HookResponse {
  // Cursor saving a chat image: check it for sensitive text (RAI-4807 #10).
  if (event.file_path && isImagePath(event.file_path)) {
    scanSavedImageInBackground({
      filePath: event.file_path,
      conversationId: event.conversation_id,
      generationId: event.generation_id,
    });
  }

  const leaked: Array<{ type: string; score: number }> = [];
  for (const edit of event.edits || []) {
    if (edit.new_string && edit.new_string.length < MAX_SCAN_SIZE) {
      leaked.push(...entitySummary(scanTextLocal(edit.new_string).entities));
    }
  }
  const action = leaked.length > 0 ? 'secret_written' : 'logged';
  if (leaked.length > 0) incStat('secretsFound', leaked.length);
  audit({
    event: 'afterFileEdit',
    action,
    filePath: event.file_path,
    entities: leaked.length > 0 ? leaked : undefined,
    ...ids(event),
  });
  return allow();
}
