/**
 * Handlers: subagentStart, afterAgentResponse, afterAgentThought
 */

import { audit, incStat } from '../lib/audit';
import { findBlockedValues } from '../lib/blocked-values';
import { allow, deny, ids } from '../lib/helpers';
import { getPolicy, globToRegex, isKeywordPattern } from '../lib/policy';
import { entitySummary, scanTextLocal } from '../lib/redaction';
import { scanResponseInBackground } from '../lib/response-scan';
import type { HookEvent, HookResponse } from '../lib/types';

export function handleSubagentStart(event: HookEvent): HookResponse {
  const task = event.task || '';
  const policy = getPolicy();
  for (const p of policy.files.blocked) {
    // A keyword pattern (`secrets*`) names a topic; a task that mentions the
    // topic is not reading a protected file (RAI-4807 #9).
    if (isKeywordPattern(p)) continue;
    if (globToRegex(p).test(task)) {
      incStat('commandsBlocked');
      audit({
        event: 'subagentStart',
        action: 'blocked',
        subagentType: event.subagent_type,
        task: task.slice(0, 200),
        reason: p,
        ...ids(event),
      });
      return deny(`Blocked subagent. Task references sensitive file pattern: ${p}.`);
    }
  }
  audit({
    event: 'subagentStart',
    action: 'allowed',
    subagentType: event.subagent_type,
    task: task.slice(0, 200),
    ...ids(event),
  });
  return allow();
}

// Patterns indicating .cursorignore blocked file access
const CURSORIGNORE_BLOCKED = [
  /permission denied/i,
  /access is blocked/i,
  /excluded.*cursorignore/i,
  /cursorignore.*excluded/i,
  /isn't exposed to tools/i,
  /can't read.*\.env/i,
  /cannot read.*\.env/i,
  /blocked.*\.env/i,
  /\.env.*not accessible/i,
];

export function handleAfterAgentResponse(event: HookEvent): HookResponse {
  const text = event.text || '';

  // Tower scans the reply against the configured security policies and records
  // the violation (RAI-4807 #6). Runs detached: the reply is already shown.
  scanResponseInBackground({
    response: text,
    ideConversationId: event.conversation_id,
    ideGenerationId: event.generation_id,
  });

  // A value blocked earlier showing up in a reply means the conversation still
  // carries it (RAI-4807 #7). The reply cannot be blocked; record it.
  const reused = findBlockedValues(text);
  if (reused.length > 0) {
    audit({
      event: 'afterAgentResponse',
      action: 'blocked_value_in_response',
      entities: reused.map((type) => ({ type, score: 1 })),
      ...ids(event),
    });
  }

  // Detect .cursorignore blocks from agent response
  const cursorignoreBlocked = CURSORIGNORE_BLOCKED.some((p) => p.test(text));
  if (cursorignoreBlocked) {
    incStat('commandsBlocked');
    audit({
      event: 'afterAgentResponse',
      action: 'data_blocked',
      reason: 'Raidu Firewall blocked sensitive file access',
      ...ids(event),
    });
    return allow();
  }

  // Scan for PII leaks in response
  const { entities } = scanTextLocal(text);
  const action = entities.length > 0 ? 'leak_in_response' : 'logged';
  if (entities.length > 0) incStat('piiFound', entities.length);
  audit({
    event: 'afterAgentResponse',
    action,
    entities: entities.length > 0 ? entitySummary(entities) : undefined,
    ...ids(event),
  });
  return allow();
}

export function handleAfterAgentThought(event: HookEvent): HookResponse {
  audit({ event: 'afterAgentThought', action: 'logged', ...ids(event) });
  return allow();
}
