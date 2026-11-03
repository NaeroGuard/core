/**
 * Converts compiled rules into Apple's Safari Content Blocker JSON format.
 *
 * @see https://developer.apple.com/documentation/safariservices/creating_a_content_blocker
 */
import { RegExpUtils } from '@adguard/agtree';
import type { CompiledRule } from './parser.js';
import type { SafariRule } from './types.js';

/**
 * Safari rejects content blocker files with too many rules, so the output is
 * capped at the documented limit.
 */
const MAX_SAFARI_RULES = 50_000;

/**
 * Wraps a regex source so it matches inside any URL under both partial-match
 * and full-match semantics: unanchored sources get `.*` on both sides, while
 * existing `^` / `$` anchors are preserved.
 */
function toUrlFilter(source: string): string {
  const anchoredStart = source.startsWith('^');
  const anchoredEnd = source.endsWith('$') && !source.endsWith('\\$');
  const body = anchoredStart ? source : `.*${source}`;
  return anchoredEnd ? body : `${body}.*`;
}

/**
 * Compiles rules into a Safari content blocker rule array.
 *
 * Block rules come first and exceptions last, because
 * `ignore-previous-rules` only affects rules that preceded it.
 */
export function compileSafariRules(
  rules: readonly CompiledRule[],
): SafariRule[] {
  const blocks: SafariRule[] = [];
  const exceptions: SafariRule[] = [];

  for (const rule of rules) {
    if (blocks.length + exceptions.length >= MAX_SAFARI_RULES) {
      console.warn(
        `NaeroGuard: truncated Safari rule output at ${MAX_SAFARI_RULES} rules`,
      );
      break;
    }

    const urlFilter = toUrlFilter(RegExpUtils.patternToRegexp(rule.pattern));
    const compiled: SafariRule =
      rule.kind === 'exception'
        ? {
            trigger: { 'url-filter': urlFilter },
            action: { type: 'ignore-previous-rules' },
          }
        : { trigger: { 'url-filter': urlFilter }, action: { type: 'block' } };

    if (rule.kind === 'exception') exceptions.push(compiled);
    else blocks.push(compiled);
  }

  return [...blocks, ...exceptions];
}
