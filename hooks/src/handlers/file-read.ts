/**
 * Handlers: beforeReadFile, beforeTabFileRead
 *
 * Files that are sensitive by nature (.env, keys, certificates, cloud
 * credentials) are blocked by NAME. Files whose name only suggests sensitivity
 * (`secrets*`, `credentials*`) are decided by their CONTENT (RAI-4807 #9).
 * Other files are not content-scanned: source code triggers false positives
 * (RAI-1893).
 */

import * as path from 'node:path';
import { audit, incStat } from '../lib/audit';
import { allow, deny, ids } from '../lib/helpers';
import { inspectFile } from '../lib/inspect';
import { classifySensitiveFile } from '../lib/policy';
import { entitySummary, formatEntities } from '../lib/redaction';
import { reportBlock, reportScanBlockIfUnrecorded } from '../lib/report';
import type { HookEvent, HookResponse } from '../lib/types';

export function handleBeforeReadFile(event: HookEvent): HookResponse {
  const filePath = event.file_path || '';
  const hit = classifySensitiveFile(filePath);

  if (hit?.mode === 'block') {
    incStat('commandsBlocked');
    audit({ event: 'beforeReadFile', action: 'blocked', filePath, reason: hit.rule, ...ids(event) });
    reportBlock(event, {
      event: 'beforeReadFile',
      kind: 'sensitive_file',
      detector: 'local',
      rule: hit.rule,
      fileName: path.basename(filePath),
    });
    return deny(`Blocked reading ${path.basename(filePath)} (policy: ${hit.rule}).`);
  }

  if (hit?.mode === 'inspect') {
    incStat('totalScans');
    const r = inspectFile(filePath, hit.rule, event.content);
    if (r.block) {
      incStat('commandsBlocked');
      audit({
        event: 'beforeReadFile',
        action: 'blocked',
        filePath,
        reason: `content (${hit.rule})`,
        entities: entitySummary(r.scan.entities),
        ...ids(event),
      });
      reportScanBlockIfUnrecorded(event, r.scan, { event: 'beforeReadFile' });
      return deny(`Blocked reading ${r.fileName}: it contains ${formatEntities(r.scan.entities)}.`);
    }
    audit({
      event: 'beforeReadFile',
      action: 'allowed',
      filePath,
      inspected: r.outcome,
      rule: hit.rule,
      ...ids(event),
    });
    return allow();
  }

  audit({ event: 'beforeReadFile', action: 'allowed', filePath, ...ids(event) });
  return allow();
}

export function handleBeforeTabFileRead(event: HookEvent): HookResponse {
  const filePath = event.file_path || '';
  // Name-only here: Tab fires on every keystroke, too often to scan content.
  // An inspect-mode file is kept out of Tab context; the agent can still read it.
  const hit = classifySensitiveFile(filePath);
  if (hit) {
    // Only log blocked Tab reads, not allowed ones (too noisy, RAI-1900)
    audit({ event: 'beforeTabFileRead', action: 'blocked', filePath, reason: hit.rule, ...ids(event) });
    return { permission: 'deny' };
  }
  // Don't log allowed Tab reads - fires on every keystroke, floods logs
  return allow();
}
