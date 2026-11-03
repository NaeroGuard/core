import { describe, expect, it } from 'vite-plus/test';
import { compileSafariRules } from './safari-compiler.js';
import { buildRuleSet, matchUrl } from './matcher.js';
import { parseRules } from './parser.js';

describe('compileSafariRules', () => {
  it('emits blocks before ignore-previous-rules entries', () => {
    const rules = parseRules([
      '||ads.test^',
      '@@||allow.test^',
      '/banner/*.jpg',
    ]);
    const compiled = compileSafariRules(rules);

    expect(compiled).toHaveLength(3);
    expect(compiled.map((rule) => rule.action.type)).toEqual([
      'block',
      'block',
      'ignore-previous-rules',
    ]);
    expect(compiled[0]?.trigger['url-filter']).toContain('ads\\.test');
    expect(compiled[1]?.trigger['url-filter']).toContain('banner');
  });

  it('returns an empty array without rules', () => {
    expect(compileSafariRules([])).toEqual([]);
  });

  it('keeps leading ^ anchors of anchored patterns', () => {
    const [compiled] = compileSafariRules(
      parseRules(['|https://evil.test/pixel']),
    );
    const urlFilter = compiled?.trigger['url-filter'] ?? '';
    expect(urlFilter.startsWith('^')).toBe(true);
    expect(new RegExp(urlFilter, 'i').test('https://evil.test/pixel')).toBe(
      true,
    );
    expect(new RegExp(urlFilter, 'i').test('https://ok.test/pixel')).toBe(
      false,
    );
  });

  it('produces url-filters that agree with the matching engine', () => {
    const sources = [
      '||tracker.com^',
      '/banner/*.jpg',
      'plain-ad',
      '|https://evil.test/pixel',
      '||good.com^',
      '@@||good.com^',
      '||example.com/ads/*',
    ];
    const rules = parseRules(sources);
    const compiled = compileSafariRules(rules);

    const blocks = compiled.filter((rule) => rule.action.type === 'block');
    const exceptions = compiled.filter((rule) => rule.action.type !== 'block');
    const set = buildRuleSet(rules);

    const urls = [
      'https://sub.tracker.com/pixel',
      'https://nottracker.com/',
      'https://a.test/banner/x.jpg',
      'https://a.test/banner/x.png',
      'https://ok.test/plain-ad.js',
      'https://ok.test/',
      'https://evil.test/pixel',
      'https://evil.test/pixel?x=1',
      'https://good.com/x',
      'https://example.com/ads/banner',
      'https://example.com/home',
    ];

    for (const url of urls) {
      const blockHit = blocks.some((rule) =>
        new RegExp(rule.trigger['url-filter'], 'i').test(url),
      );
      const exceptionHit = exceptions.some((rule) =>
        new RegExp(rule.trigger['url-filter'], 'i').test(url),
      );
      const safariBlocked = blockHit && !exceptionHit;
      const engineBlocked = matchUrl(url, set)?.blocked ?? false;
      expect(safariBlocked, url).toBe(engineBlocked);
    }
  });
});
