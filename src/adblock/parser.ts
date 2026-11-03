/**
 * Parses raw AdGuard / uBlock Origin / Adblock Plus filter lists into a small
 * set of compiled network rules that the matcher can evaluate quickly.
 *
 * Parsing itself is delegated to `@adguard/agtree`, which produces a full AST;
 * cosmetic rules, comments and empty lines are simply not part of the result.
 */
import {
  FilterListParser,
  NetworkRuleType,
  RegExpUtils,
  RuleCategory,
} from '@adguard/agtree';
import type {
  FilterList,
  HostRule,
  Modifier,
  NetworkRule,
} from '@adguard/agtree';

export type RuleKind = 'block' | 'exception';

export interface CompiledRuleBase {
  kind: RuleKind;
  /** Original filter-list line, reported back as `rule_matched`. */
  source: string;
  /** Pattern without modifiers — the input for Safari compilation. */
  pattern: string;
  /** `$important` rules are checked before exceptions and win over them. */
  important: boolean;
}

/** `||host…` — matched by looking up the URL hostname and its parent domains. */
export interface DomainRule extends CompiledRuleBase {
  type: 'domain';
  /** Lowercased hostname part of the pattern, e.g. `example.com`. */
  host: string;
  /** Pattern after the host part, e.g. `^` or `/ads/*`. */
  rest: string;
  /** Matches the URL part right after the hostname, anchored at its start. */
  restRe: RegExp | null;
}

/** Pattern without adblock metacharacters — a plain case-insensitive substring test. */
export interface SubstringRule extends CompiledRuleBase {
  type: 'substring';
  /** Lowercased pattern used for the substring test. */
  needle: string;
}

/** Everything else, precompiled to a RegExp over the full URL. */
export interface RegexRule extends CompiledRuleBase {
  type: 'regex';
  re: RegExp;
  /** Lowercased literal every matching URL contains; `null` disables the shortcut. */
  prefilter: string | null;
}

export type CompiledRule = DomainRule | SubstringRule | RegexRule;

/** Characters that end the host part of a `||`-anchored pattern. */
const HOST_PART_END = '/?#^*|:';

/** Shortest literal worth using as a regex prefilter. */
const MIN_PREFILTER_LENGTH = 4;

/**
 * Modifiers that turn a rule into something other than a plain request block
 * (header/response rewriting, cosmetic exceptions, ...). Those rules are
 * dropped rather than misreported as blocks.
 */
const NON_BLOCKING_MODIFIERS = new Set([
  'csp',
  'replace',
  'removeparam',
  'urltransform',
  'header',
  'removeheader',
  'method',
  'permissions',
  'jsonprune',
  'set-cookie',
  'generichide',
  'genericblock',
  'elemhide',
  'specifichide',
  'ehide',
  'shide',
]);

/** Hosts-file addresses that mean "block this hostname". */
const BLOCKING_IPS = new Set([
  '0.0.0.0',
  '127.0.0.1',
  '::',
  '::1',
  '0:0:0:0:0:0:0:0',
  '0:0:0:0:0:0:0:1',
]);

/**
 * Extracts the longest unconditional literal from a regex source so the regex
 * itself can be skipped when the URL does not contain it. Conservative: any
 * construct that could make a literal optional or conditional (alternation,
 * quantifiers, groups, character classes) discards it.
 */
function extractPrefilter(regexSource: string): string | null {
  let best = '';
  let run = '';
  let depth = 0;
  let inClass = false;

  const flush = (required: boolean): void => {
    if (required && run.length > best.length) best = run;
    run = '';
  };

  for (let i = 0; i < regexSource.length; i += 1) {
    const char = regexSource[i];

    if (inClass) {
      if (char === '\\') i += 1;
      else if (char === ']') inClass = false;
      continue;
    }

    if (char === '\\') {
      const escaped = regexSource[i + 1];
      if (escaped === undefined) break;
      if (depth === 0) run += escaped;
      i += 1;
      continue;
    }

    if (char === '[') {
      flush(false);
      inClass = true;
      continue;
    }
    if (char === '(') {
      flush(false);
      depth += 1;
      continue;
    }
    if (char === ')') {
      flush(false);
      if (depth > 0) depth -= 1;
      continue;
    }
    if (char === '|') {
      // Top-level alternation: no single branch is guaranteed.
      if (depth === 0) return null;
      continue;
    }
    if (char === '?' || char === '*') {
      flush(false);
      continue;
    }
    if (char === '+') {
      // The last atom occurs at least once, so the run stays required.
      flush(true);
      continue;
    }
    if (char === '{') {
      flush(false);
      while (i + 1 < regexSource.length && regexSource[i + 1] !== '}') i += 1;
      i += 1;
      continue;
    }
    if (char === '^' || char === '$' || char === '.' || char === '}') {
      flush(false);
      continue;
    }
    if (depth === 0) run += char;
  }

  flush(!inClass && depth === 0);
  return best.length >= MIN_PREFILTER_LENGTH ? best.toLowerCase() : null;
}

function regexRule(base: CompiledRuleBase, pattern: string): RegexRule {
  const source = RegExpUtils.patternToRegexp(pattern);
  return {
    ...base,
    type: 'regex',
    re: new RegExp(source, 'i'),
    prefilter: extractPrefilter(source),
  };
}

function domainRule(
  base: CompiledRuleBase,
  pattern: string,
): DomainRule | null {
  const after = pattern.slice(2);
  let end = 0;
  while (end < after.length && !HOST_PART_END.includes(after[end])) end += 1;
  const host = after.slice(0, end).toLowerCase();
  if (host.length === 0) return null;
  const rest = after.slice(end);
  // An empty rest (or a bare `^`) matches any port/path/query after the host.
  const restRe =
    rest === '' || rest === '^'
      ? null
      : new RegExp(`^${RegExpUtils.patternToRegexp(rest)}`, 'i');
  return { ...base, type: 'domain', host, rest, restRe };
}

function classify(
  pattern: string,
  source: string,
  kind: RuleKind,
  important: boolean,
): CompiledRule {
  const base = { source, pattern, kind, important };

  // AdGuard-style `/regex/` patterns are compiled as regexes, not substrings.
  if (RegExpUtils.isRegexPattern(pattern)) return regexRule(base, pattern);

  if (pattern.startsWith('||')) {
    const domain = domainRule(base, pattern);
    if (domain !== null) return domain;
  }

  if (
    pattern.includes('*') ||
    pattern.includes('^') ||
    pattern.startsWith('|') ||
    pattern.endsWith('|')
  ) {
    return regexRule(base, pattern);
  }

  return { ...base, type: 'substring', needle: pattern.toLowerCase() };
}

function ruleKey(
  kind: RuleKind,
  pattern: string,
  modifiers: readonly Modifier[],
): string {
  const mods = modifiers
    .filter((modifier) => modifier.name.value !== 'badfilter')
    .map((modifier) =>
      modifier.value
        ? `${modifier.name.value}=${modifier.value.value}`
        : modifier.name.value,
    )
    .sort()
    .join(',');
  return `${kind}\u0000${pattern}\u0000${mods}`;
}

function collectNetworkRule(
  node: NetworkRule,
  entries: Array<{ rule: CompiledRule; key: string }>,
  badfilters: Set<string>,
): void {
  const pattern = node.pattern.value;
  const modifiers = node.modifiers?.children ?? [];
  const names = modifiers.map((modifier) => modifier.name.value);
  const kind: RuleKind = node.exception ? 'exception' : 'block';
  const key = ruleKey(kind, pattern, modifiers);

  if (names.includes('badfilter')) {
    badfilters.add(key);
    return;
  }
  if (names.some((name) => NON_BLOCKING_MODIFIERS.has(name))) return;

  entries.push({
    rule: classify(
      pattern,
      node.raws?.text ?? pattern,
      kind,
      names.includes('important'),
    ),
    key,
  });
}

function collectHostRule(
  node: HostRule,
  entries: Array<{ rule: CompiledRule; key: string }>,
): void {
  if (!BLOCKING_IPS.has(node.ip.value)) return;
  const source =
    node.raws?.text ??
    node.hostnames.children.map((hostname) => hostname.value).join(' ');
  for (const hostname of node.hostnames.children) {
    const pattern = `||${hostname.value}^`;
    entries.push({
      rule: classify(pattern, source, 'block', false),
      key: ruleKey('block', pattern, []),
    });
  }
}

/**
 * Parses one or more raw filter lists into compiled network rules.
 *
 * Lists are tolerant to syntactically broken lines; a list that cannot be
 * parsed at all is skipped with a warning instead of failing the request.
 * `$badfilter` is applied across all given sources.
 */
export function parseRules(sources: readonly string[]): CompiledRule[] {
  const entries: Array<{ rule: CompiledRule; key: string }> = [];
  const badfilters = new Set<string>();

  for (const raw of sources) {
    let list: FilterList;
    try {
      list = FilterListParser.parse(raw, {
        tolerant: true,
        isLocIncluded: false,
        parseHostRules: true,
        includeRaws: true,
      });
    } catch (error) {
      console.warn('NaeroGuard: skipped an unparseable filter list', error);
      continue;
    }

    for (const node of list.children) {
      if (node.category !== RuleCategory.Network) continue;
      if (node.type === NetworkRuleType.HostRule)
        collectHostRule(node, entries);
      else collectNetworkRule(node, entries, badfilters);
    }
  }

  return entries
    .filter((entry) => !badfilters.has(entry.key))
    .map((entry) => entry.rule);
}
