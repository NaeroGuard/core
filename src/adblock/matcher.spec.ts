import { describe, expect, it } from 'vite-plus/test';
import { buildRuleSet, matchUrl, normalizeUrl } from './matcher.js';
import { parseRules } from './parser.js';

function setOf(list: string[]) {
  return buildRuleSet(parseRules(list));
}

describe('normalizeUrl', () => {
  it('parses absolute URLs', () => {
    expect(normalizeUrl('https://example.com/x')).toMatchObject({
      href: 'https://example.com/x',
      hostname: 'example.com',
      rest: '/x',
    });
  });

  it('parses scheme-less hosts', () => {
    expect(normalizeUrl('ads.example.com/x')?.href).toBe(
      'https://ads.example.com/x',
    );
  });

  it('strips a trailing dot from the hostname', () => {
    const url = normalizeUrl('https://example.com./x');
    expect(url?.hostname).toBe('example.com');
    expect(url?.rest).toBe('/x');
  });

  it('returns null for unparseable input', () => {
    expect(normalizeUrl('not a url at all')).toBeNull();
  });
});

describe('matchUrl', () => {
  it('matches domain rules on subdomains', () => {
    const set = setOf(['||tracker.com^']);
    expect(matchUrl('https://sub.tracker.com/pixel', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://tracker.com/x', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://nottracker.com/', set)).toMatchObject({
      blocked: false,
    });
  });

  it('does not match a lookalike suffix domain', () => {
    const set = setOf(['||tracker.com^']);
    expect(matchUrl('https://tracker.com.evil.test/', set)).toMatchObject({
      blocked: false,
    });
  });

  it('honors the path part of domain rules', () => {
    const set = setOf(['||example.com/ads/*']);
    expect(matchUrl('https://example.com/ads/banner', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://sub.example.com/ads/banner', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://example.com/home', set)).toMatchObject({
      blocked: false,
    });
    // AdGuard: the pattern continues right after the hostname, so a port in
    // between prevents the path from matching (same as patternToRegexp).
    expect(matchUrl('https://example.com:8443/ads/banner', set)).toMatchObject({
      blocked: false,
    });
  });

  it('matches across ports with a separator + wildcard pattern', () => {
    const set = setOf(['||example.com^*ads*']);
    expect(matchUrl('https://example.com:8443/ads/banner', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://example.com/ads/banner', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://example.com:8443/home', set)).toMatchObject({
      blocked: false,
    });
  });

  it('consumes exactly one separator for a mid-pattern ^', () => {
    // `^` eats the single `/` after the host, so the pattern needs another `/`.
    const set = setOf(['||example.com^/ads/*']);
    expect(matchUrl('https://example.com//ads/banner', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://example.com/ads/banner', set)).toMatchObject({
      blocked: false,
    });
  });

  it('lets exceptions win over regular blocks', () => {
    const set = setOf(['||good.com^', '@@||good.com^']);
    expect(matchUrl('https://good.com/x', set)).toMatchObject({
      blocked: false,
    });
  });

  it('lets $important blocks win over exceptions', () => {
    const set = setOf(['||ads.test^$important', '@@||ads.test^']);
    expect(matchUrl('https://ads.test/x', set)).toMatchObject({
      blocked: true,
    });
  });

  it('matches substring rules case-insensitively', () => {
    const set = setOf(['ads/banner']);
    expect(matchUrl('https://x.test/ADS/BANNER.js', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://x.test/ok.js', set)).toMatchObject({
      blocked: false,
    });
  });

  it('matches wildcard rules', () => {
    const set = setOf(['/banner/*.jpg']);
    expect(matchUrl('https://a.test/banner/x.jpg', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://a.test/banner/x.png', set)).toMatchObject({
      blocked: false,
    });
  });

  it('matches regex rules', () => {
    const set = setOf(['|https://evil.test/pixel']);
    expect(matchUrl('https://evil.test/pixel', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://evil.test/pixel2', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://ok.test/pixel', set)).toMatchObject({
      blocked: false,
    });
  });

  it('matches host-file rules', () => {
    const set = setOf(['0.0.0.0 ads.hostfile.test']);
    expect(matchUrl('https://ads.hostfile.test/', set)).toMatchObject({
      blocked: true,
    });
    expect(matchUrl('https://ok.hostfile.test/', set)).toMatchObject({
      blocked: false,
    });
  });

  it('returns null for unparseable URLs', () => {
    expect(matchUrl('not a url at all', setOf(['||x.test^']))).toBeNull();
  });

  it('returns an unblocked result when no rules exist', () => {
    expect(matchUrl('https://example.com/', buildRuleSet([]))).toEqual({
      blocked: false,
    });
  });

  it('prefilter never changes a regex rule decision', () => {
    const rules = parseRules([
      '/ads[0-9]+/',
      '/banner/*.jpg',
      '|https://evil.test/pixel',
      '/^https?:\\/\\/cdn\\.[a-z]+\\.test\\//',
    ]);
    const candidates = [
      'https://a.test/ads1.js',
      'https://a.test/banner/x.jpg',
      'https://evil.test/pixel',
      'https://evil.test/pixel?x=1',
      'https://cdn.foo.test/app.js',
      'https://ok.test/',
      'https://a.test/ads',
    ];

    for (const rule of rules) {
      if (rule.type !== 'regex') continue;
      for (const url of candidates) {
        const direct = rule.re.test(url);
        if (rule.prefilter === null) continue;
        const prefiltered =
          url.toLowerCase().includes(rule.prefilter) && rule.re.test(url);
        expect(prefiltered).toBe(direct);
      }
    }
  });

  it('reports the matching rule for rule_matched', () => {
    const set = setOf(['||tracker.com^']);
    expect(matchUrl('https://sub.tracker.com/pixel', set)?.rule?.source).toBe(
      '||tracker.com^',
    );
  });
});
