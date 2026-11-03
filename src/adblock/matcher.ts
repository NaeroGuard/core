/**
 * URL matching against a compiled rule set.
 *
 * Speed comes from three tiers, tried in order:
 *  1. domain-anchored rules — a `Map` lookup per hostname label (O(labels)),
 *  2. plain substring rules — a case-insensitive `includes` scan,
 *  3. regex rules — guarded by a required-literal prefilter.
 */
import type {
  CompiledRule,
  DomainRule,
  RegexRule,
  SubstringRule,
} from './parser.js';

interface RuleIndex {
  domain: Map<string, DomainRule[]>;
  substr: SubstringRule[];
  regex: RegexRule[];
}

export interface RuleSet {
  /** `$important` blocks — checked first and not overridable by exceptions. */
  important: RuleIndex;
  block: RuleIndex;
  except: RuleIndex;
}

export interface NormalizedUrl {
  /** Full URL as produced by the WHATWG parser (scheme lowercased, host normalized). */
  href: string;
  hrefLower: string;
  hostname: string;
  /** Part of `href` right after the hostname: port, path, query and hash. */
  rest: string;
}

export interface MatchResult {
  blocked: boolean;
  /** The rule that decided the outcome, if any. */
  rule?: CompiledRule;
}

/** Scheme plus optional userinfo — everything that precedes the hostname. */
const SCHEME_AND_USERINFO = /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/(?:[^/?#]*@)?/;

/**
 * Parses a user-supplied URL. Bare hosts such as `ads.example.com/x` are
 * retried with an `https://` prefix. Returns `null` when nothing parses.
 */
export function normalizeUrl(raw: string): NormalizedUrl | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    try {
      url = new URL(`https://${raw}`);
    } catch {
      return null;
    }
  }

  const href = url.href;
  const hostnameWithDot = url.hostname;
  const match = SCHEME_AND_USERINFO.exec(href);
  const hostStart = match === null ? 0 : match[0].length;
  const hostname = hostnameWithDot.endsWith('.')
    ? hostnameWithDot.slice(0, -1)
    : hostnameWithDot;

  return {
    href,
    hrefLower: href.toLowerCase(),
    hostname,
    rest: href.slice(hostStart + hostnameWithDot.length),
  };
}

function emptyIndex(): RuleIndex {
  return { domain: new Map(), substr: [], regex: [] };
}

function addToIndex(
  index: RuleIndex,
  rule: DomainRule | SubstringRule | RegexRule,
): void {
  if (rule.type === 'domain') {
    const existing = index.domain.get(rule.host);
    if (existing === undefined) index.domain.set(rule.host, [rule]);
    else existing.push(rule);
  } else if (rule.type === 'substring') {
    index.substr.push(rule);
  } else {
    index.regex.push(rule);
  }
}

export function buildRuleSet(rules: readonly CompiledRule[]): RuleSet {
  const set: RuleSet = {
    important: emptyIndex(),
    block: emptyIndex(),
    except: emptyIndex(),
  };
  for (const rule of rules) {
    if (rule.kind === 'exception') addToIndex(set.except, rule);
    else if (rule.important) addToIndex(set.important, rule);
    else addToIndex(set.block, rule);
  }
  return set;
}

function findInIndex(
  index: RuleIndex,
  url: NormalizedUrl,
): CompiledRule | undefined {
  // 1) Domain-anchored rules: walk the hostname and its parent domains.
  let host = url.hostname;
  for (;;) {
    const candidates = index.domain.get(host);
    if (candidates !== undefined) {
      for (const rule of candidates) {
        if (rule.restRe === null || rule.restRe.test(url.rest)) return rule;
      }
    }
    const dot = host.indexOf('.');
    if (dot === -1) break;
    host = host.slice(dot + 1);
  }

  // 2) Plain substring rules.
  for (const rule of index.substr) {
    if (url.hrefLower.includes(rule.needle)) return rule;
  }

  // 3) Regex rules, skipped early when a required literal is missing.
  for (const rule of index.regex) {
    if (rule.prefilter !== null && !url.hrefLower.includes(rule.prefilter))
      continue;
    if (rule.re.test(url.href)) return rule;
  }

  return undefined;
}

/**
 * Checks a URL against a rule set.
 *
 * Precedence: `$important` blocks, then exceptions, then regular blocks.
 * Returns `null` when the URL cannot be parsed at all.
 */
export function matchUrl(raw: string, set: RuleSet): MatchResult | null {
  const url = normalizeUrl(raw);
  if (url === null) return null;

  const important = findInIndex(set.important, url);
  if (important !== undefined) return { blocked: true, rule: important };

  const exception = findInIndex(set.except, url);
  if (exception !== undefined) return { blocked: false, rule: exception };

  const block = findInIndex(set.block, url);
  if (block !== undefined) return { blocked: true, rule: block };

  return { blocked: false };
}
