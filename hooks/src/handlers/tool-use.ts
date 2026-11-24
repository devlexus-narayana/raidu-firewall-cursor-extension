/**
 * Handler: preToolUse
 *
 * - Blocks access to files that are sensitive by NAME (.env, keys, ...).
 * - Files whose name only suggests sensitivity (`secrets*`) are decided by
 *   their content (RAI-4807 #9). Other files are not content-scanned: source
 *   code triggers false positives (RAI-1893).
 * - Blocks any tool input (a Write, an Edit, a command, MCP arguments) that
 *   carries a value the firewall blocked earlier (RAI-4807 #7).
 * - Scans shell commands for secrets and exfiltration patterns.
 */

import { audit, incStat } from '../lib/audit';
import { findBlockedValues, rememberBlockedValues } from '../lib/blocked-values';
import { allow, deny, ids } from '../lib/helpers';
import { inspectFile } from '../lib/inspect';
import { type FileToInspect, findSensitiveToolAccess } from '../lib/policy';
import { entitySummary, formatEntities, scanText } from '../lib/redaction';
import { reportBlock, reportScanBlockIfUnrecorded } from '../lib/report';
import type { HookEvent, HookResponse } from '../lib/types';

const EXFIL_PATTERNS: RegExp[] = [/curl\s+.*(-d|--data)/i, /wget\s+.*--post/i, /scp\s+.*@/, /rsync\s+.*@/, /nc\s+-/];

export function handlePreToolUse(event: HookEvent): HookResponse {
  const tool = event.tool_name || '';
  const input = event.tool_input || {};

  // A value blocked earlier must not be written, run or sent by the agent.
  const reused = findBlockedValues(JSON.stringify(input));
  if (reused.length > 0) {
    incStat('commandsBlocked');
    audit({
      event: 'preToolUse',
      action: 'blocked',
      tool,
      reason: 'previously_blocked_value',
      entities: reused.map((type) => ({ type, score: 1 })),
      ...ids(event),
    });
    reportBlock(event, {
      event: 'preToolUse',
      kind: 'sensitive_data',
      detector: 'local',
      tool,
      entityTypes: reused,
      rule: 'previously_blocked_value',
    });
    return deny(
      `Blocked ${tool}: it uses a value Raidu Firewall blocked earlier (${reused.join(', ')}). Ask the user to provide it through an approved workflow instead.`,
    );
  }

  // Block access to files that are sensitive by name; collect the ones to inspect.
  const toInspect: FileToInspect[] = [];
  const hit = findSensitiveToolAccess(input, toInspect);
  if (hit) {
    incStat('commandsBlocked');
    audit({ event: 'preToolUse', action: 'blocked', tool, reason: hit.message, ...ids(event) });
    reportBlock(event, {
      event: 'preToolUse',
      kind: hit.kind,
      detector: 'local',
      tool,
      rule: hit.rule,
      fileName: hit.fileName,
    });
    return deny(hit.message);
  }

  for (const f of toInspect.slice(0, 5)) {
    incStat('totalScans');
    const r = inspectFile(f.filePath, f.rule, undefined, event.cwd);
    if (r.block) {
      incStat('commandsBlocked');
      audit({
        event: 'preToolUse',
        action: 'blocked',
        tool,
        reason: `content (${f.rule})`,
        entities: entitySummary(r.scan.entities),
        ...ids(event),
      });
      reportScanBlockIfUnrecorded(event, r.scan, { event: 'preToolUse', tool });
      return deny(`Blocked access to ${r.fileName}: it contains ${formatEntities(r.scan.entities)}.`);
    }
  }

  // Scan Shell/Bash commands for secrets + exfiltration
  if ((tool === 'Shell' || tool === 'Bash') && input.command) {
    incStat('totalScans');
    const scan = scanText(input.command as string);
    const { entities } = scan;
    if (entities.length > 0) {
      incStat('piiFound', entities.length);
      incStat('commandsBlocked');
      audit({
        event: 'preToolUse',
        action: 'blocked',
        tool,
        command: (input.command as string).slice(0, 500),
        entities: entitySummary(entities),
        ...ids(event),
      });
      rememberBlockedValues(entities);
      reportScanBlockIfUnrecorded(event, scan, { event: 'preToolUse', tool });
      return deny(`Blocked command. Contains ${formatEntities(entities)}.`);
    }
    if (EXFIL_PATTERNS.some((p) => p.test(input.command as string))) {
      incStat('commandsBlocked');
      audit({
        event: 'preToolUse',
        action: 'blocked',
        tool,
        command: (input.command as string).slice(0, 500),
        reason: 'data exfiltration',
        ...ids(event),
      });
      reportBlock(event, { event: 'preToolUse', kind: 'exfiltration', detector: 'local', tool });
      return deny('Blocked command. Data exfiltration pattern detected.');
    }
  }

  audit({ event: 'preToolUse', action: 'allowed', tool, ...ids(event) });
  return allow();
}
