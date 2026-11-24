/**
 * Policy management: file sensitivity, command blocking, glob matching.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { LOG_DIR } from './audit';
import type { Policy } from './types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const POLICY_CACHE = path.join(LOG_DIR, 'policy.json');

export const DEFAULT_POLICY: Policy = {
  files: {
    blocked: [
      '.env',
      '.env.local',
      '.env.production',
      '.env.staging',
      '.env.development',
      '*.env',
      'credentials*',
      'secrets*',
      '*.pem',
      '*.key',
      '*.p12',
      '*.pfx',
      '*.jks',
      '*.keystore',
      'id_rsa',
      'id_ed25519',
      'id_ecdsa',
      '.netrc',
      '.pgpass',
      '.npmrc',
      '.pypirc',
      '.aws/*',
      '.aws/credentials',
      '.ssh/*',
      '.kube/*',
      '.kube/config',
      'docker-compose*.yml',
      'docker-compose*.yaml',
    ],
    allowed: ['.env.example', '.env.sample', '.env.template'],
  },
  commands: {
    blocked: [
      'printenv',
      'env$',
      'set$',
      'echo.*\\$.*KEY',
      'echo.*\\$.*SECRET',
      'echo.*\\$.*TOKEN',
      'echo.*\\$.*PASSWORD',
    ],
  },
};

// ---------------------------------------------------------------------------
// Policy loader
// ---------------------------------------------------------------------------

export function getPolicy(): Policy {
  let policy = { ...DEFAULT_POLICY, files: { ...DEFAULT_POLICY.files, blocked: [...DEFAULT_POLICY.files.blocked] } };

  // Try API-cached policy
  try {
    const cached = JSON.parse(fs.readFileSync(POLICY_CACHE, 'utf-8'));
    if (cached?.files?.blocked && Array.isArray(cached.files.blocked) && cached.files.blocked.length > 0) {
      policy = cached as Policy;
    }
  } catch {}

  // Merge .cursorignore if it exists in the project
  const projectDir = process.env.CURSOR_PROJECT_DIR || process.cwd();
  try {
    const content = fs.readFileSync(path.join(projectDir, '.cursorignore'), 'utf-8');
    const existing = new Set(policy.files.blocked);
    for (const line of content.split('\n')) {
      const p = line.trim();
      if (p && !p.startsWith('#') && !existing.has(p)) {
        policy.files.blocked.push(p);
        existing.add(p);
      }
    }
  } catch {}

  return policy;
}

// ---------------------------------------------------------------------------
// Glob / sensitivity helpers
// ---------------------------------------------------------------------------

/**
 * Unanchored glob, for testing a pattern against free text (a subagent task,
 * a search glob). File names are matched with matchesFilePattern() instead.
 */
export function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // escape regex specials (not *)
    .replace(/\*/g, '.*'); // convert glob * to regex .*
  return new RegExp(escaped, 'i');
}

/** Anchored glob: `*` matches within one path segment. */
function anchoredGlob(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return new RegExp(`^${escaped}$`, 'i');
}

function toPosix(p: string): string {
  return p.replace(/\\/g, '/');
}

/**
 * Does a policy pattern match this file?
 *
 * Patterns without a slash match the file NAME exactly (`.env` matches `.env`,
 * not `.environment.ts`; `*.key` matches `server.key`, not `keyboard.key.ts`
 * nor `foo.keyboard`). Patterns with a slash match the trailing path segments
 * (`.aws/*` matches `/home/me/.aws/config`). The old matcher was an unanchored
 * substring test, which blocked any file whose path merely CONTAINED a pattern.
 */
export function matchesFilePattern(pattern: string, filePath: string): boolean {
  const p = toPosix(pattern.trim()).replace(/\/+$/, '');
  if (!p) return false;
  const full = toPosix(filePath);
  const segments = full.split('/').filter(Boolean);
  if (!p.includes('/')) {
    // A bare directory name in .cursorignore ("secrets") protects everything below it.
    return segments.some((seg, i) => anchoredGlob(p).test(seg) && (i === segments.length - 1 || !p.includes('*')));
  }
  const patSegs = p.replace(/^\/+/, '').split('/').filter(Boolean);
  for (let start = 0; start + patSegs.length <= segments.length; start++) {
    if (patSegs.every((ps, k) => anchoredGlob(ps).test(segments[start + k]))) return true;
  }
  return false;
}

/**
 * A keyword pattern names a TOPIC, not a file type: `secrets*`, `*private*`,
 * `credentials*`. It has a wildcard and no extension or path. A file matching
 * only a keyword pattern is not blocked by name (RAI-4807 #9): its content is
 * scanned and decides. Patterns for formats that are sensitive by nature
 * (`.env`, `*.pem`, `id_rsa`, `.ssh/*`) still block on the name.
 */
export function isKeywordPattern(pattern: string): boolean {
  const p = pattern.trim();
  return p.includes('*') && !p.includes('.') && !p.includes('/');
}

export interface SensitiveFileMatch {
  /** The policy pattern that matched. */
  rule: string;
  /** 'block' = sensitive by name; 'inspect' = name only suggests it, scan the content. */
  mode: 'block' | 'inspect';
}

export function classifySensitiveFile(filePath: string): SensitiveFileMatch | null {
  if (!filePath) return null;
  const policy = getPolicy();

  for (const p of policy.files.allowed || []) {
    if (matchesFilePattern(p, filePath)) return null;
  }
  let keywordHit: string | null = null;
  for (const p of policy.files.blocked) {
    if (!matchesFilePattern(p, filePath)) continue;
    if (!isKeywordPattern(p)) return { rule: p, mode: 'block' };
    keywordHit ??= p;
  }
  return keywordHit ? { rule: keywordHit, mode: 'inspect' } : null;
}

/** The matching pattern when a file is protected by NAME alone; null otherwise. */
export function isSensitiveFile(filePath: string): string | null {
  const hit = classifySensitiveFile(filePath);
  return hit?.mode === 'block' ? hit.rule : null;
}

/** Path-like tokens in a shell command (`cat ~/.aws/credentials | ...`). */
export function commandPathTokens(command: string): string[] {
  return command
    .split(/[\s|&;<>()$`'"=]+/)
    .map((t) => t.replace(/^~(?=\/)/, ''))
    .filter((t) => t && !t.startsWith('-'));
}

export interface SensitiveToolAccess {
  /** User-facing reason, as shown in the deny message. */
  message: string;
  kind: 'sensitive_file' | 'command_policy';
  /** The policy pattern that matched. */
  rule: string;
  /** Basename of the file, when the tool named one. */
  fileName?: string;
}

/**
 * A file the tool would touch whose name only suggests sensitivity. The caller
 * decides by scanning its content (RAI-4807 #9).
 */
export interface FileToInspect {
  filePath: string;
  rule: string;
}

export function findSensitiveToolAccess(
  toolInput: Record<string, unknown>,
  inspect?: FileToInspect[],
): SensitiveToolAccess | null {
  const policy = getPolicy();

  if (toolInput.file_path) {
    const filePath = toolInput.file_path as string;
    const hit = classifySensitiveFile(filePath);
    if (hit?.mode === 'block') {
      const fileName = path.basename(filePath);
      return {
        message: `Blocked access to ${fileName} (policy: ${hit.rule})`,
        kind: 'sensitive_file',
        rule: hit.rule,
        fileName,
      };
    }
    if (hit) inspect?.push({ filePath, rule: hit.rule });
  }

  if (toolInput.glob) {
    // Listing names is not reading content, so keyword patterns do not apply.
    for (const p of policy.files.blocked) {
      if (isKeywordPattern(p)) continue;
      if (globToRegex(p).test(toolInput.glob as string))
        return { message: `Blocked search for sensitive files (${toolInput.glob})`, kind: 'sensitive_file', rule: p };
    }
  }

  if (toolInput.command) {
    const command = toolInput.command as string;
    for (const token of commandPathTokens(command)) {
      const hit = classifySensitiveFile(token);
      if (hit?.mode === 'block')
        return { message: `Blocked shell access to ${hit.rule}`, kind: 'sensitive_file', rule: hit.rule };
      if (hit) inspect?.push({ filePath: token, rule: hit.rule });
    }
    for (const p of policy.commands.blocked) {
      try {
        if (new RegExp(p, 'i').test(command))
          return { message: `Blocked command (policy: ${p})`, kind: 'command_policy', rule: p };
      } catch {}
    }
  }

  return null;
}

export function checkToolInputForSensitiveFiles(toolInput: Record<string, unknown>): string | null {
  return findSensitiveToolAccess(toolInput)?.message ?? null;
}
