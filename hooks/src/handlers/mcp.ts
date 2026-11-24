/**
 * Handler: beforeMCPExecution
 */

import { audit, incStat } from '../lib/audit';
import { findBlockedValues, rememberBlockedValues } from '../lib/blocked-values';
import { allow, deny, ids } from '../lib/helpers';
import { entitySummary, formatEntities, scanText } from '../lib/redaction';
import { reportBlock, reportScanBlockIfUnrecorded } from '../lib/report';
import type { HookEvent, HookResponse } from '../lib/types';

export function handleBeforeMCPExecution(event: HookEvent): HookResponse {
  const inputStr = typeof event.tool_input === 'string' ? event.tool_input : JSON.stringify(event.tool_input || '');
  const reused = findBlockedValues(inputStr);
  if (reused.length > 0) {
    incStat('commandsBlocked');
    audit({
      event: 'beforeMCPExecution',
      action: 'blocked',
      tool: event.tool_name,
      reason: 'previously_blocked_value',
      entities: reused.map((type) => ({ type, score: 1 })),
      ...ids(event),
    });
    reportBlock(event, {
      event: 'beforeMCPExecution',
      kind: 'sensitive_data',
      detector: 'local',
      tool: event.tool_name,
      entityTypes: reused,
      rule: 'previously_blocked_value',
    });
    return deny(
      `Blocked MCP tool ${event.tool_name}. Its input uses a value Raidu Firewall blocked earlier (${reused.join(', ')}).`,
    );
  }
  const scan = scanText(inputStr);
  const { entities } = scan;
  if (entities.length > 0) {
    incStat('commandsBlocked');
    audit({
      event: 'beforeMCPExecution',
      action: 'blocked',
      tool: event.tool_name,
      entities: entitySummary(entities),
      ...ids(event),
    });
    rememberBlockedValues(entities);
    reportScanBlockIfUnrecorded(event, scan, { event: 'beforeMCPExecution', tool: event.tool_name });
    return deny(`Blocked MCP tool ${event.tool_name}. Input contains ${formatEntities(entities)}.`);
  }
  audit({ event: 'beforeMCPExecution', action: 'allowed', tool: event.tool_name, ...ids(event) });
  return allow();
}
