import { describe, expect, it } from 'vite-plus/test';
import { parseRules } from './parser.js';

describe('parseRules', () => {
  it('compiles domain-anchored rules', () => {
    const rules = parseRules(['||tracker.com^']);
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({
      type: 'domain',
      kind: 'block',
      host: 'tracker.com',
      rest: '^',
      restRe: null,
      important: false,
      source: '||tracker.com^',
      pattern: '||tracker.com^',
    });
  });

  it('keeps the path part of domain-anchored rules', () => {
    const [rule] = parseRules(['||example.com/ads/*']);
    expect(rule).toMatchObject({
      type: 'domain',
      host: 'example.com',
      rest: '/ads/*',
    });
    if (rule?.type !== 'domain' || rule.restRe === null)
      throw new Error('expected restRe');
    expect(rule.restRe.test('/ads/banner')).toBe(true);
    expect(rule.restRe.test('/other')).toBe(false);
  });

  it('marks exceptions', () => {
    const [rule] = parseRules(['@@||good.com^']);
    expect(rule?.kind).toBe('exception');
  });

  it('flags $important rules', () => {
    const [rule] = parseRules(['||ads.test^$important']);
    expect(rule?.important).toBe(true);
  });

  it('skips cosmetic rules, comments and empty lines', () => {
    const rules = parseRules([
      '! comment',
      '',
      '##.ad-banner',
      'example.com##.promo',
    ]);
    expect(rules).toHaveLength(0);
  });

  it('classifies plain patterns as substring rules', () => {
    const [rule] = parseRules(['plain-ad']);
    expect(rule).toMatchObject({ type: 'substring', needle: 'plain-ad' });
  });

  it('classifies wildcard patterns as regex rules', () => {
    const [rule] = parseRules(['/banner/*.jpg']);
    expect(rule?.type).toBe('regex');
  });

  it('classifies /regex/ patterns as regex rules', () => {
    const [rule] = parseRules(['/ads[0-9]+/']);
    expect(rule?.type).toBe('regex');
  });

  it('keeps the original line as source for exceptions', () => {
    const [rule] = parseRules(['@@||good.com^']);
    expect(rule?.source).toBe('@@||good.com^');
  });

  it('applies $badfilter across all sources', () => {
    const rules = parseRules(['||tracker.com^', '||tracker.com^$badfilter']);
    expect(rules).toHaveLength(0);
  });

  it('does not strip a badfiltered rule when modifiers differ', () => {
    const rules = parseRules([
      '||tracker.com^$third-party',
      '||tracker.com^$badfilter',
    ]);
    expect(rules).toHaveLength(1);
  });

  it('drops rules with response-rewriting modifiers', () => {
    const rules = parseRules([
      '||tracker.com^$removeparam=utm',
      '||tracker.com^$csp=a',
    ]);
    expect(rules).toHaveLength(0);
  });

  it('converts hosts-file rules into domain rules', () => {
    const rules = parseRules(['0.0.0.0 hostsblock.test']);
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({
      type: 'domain',
      kind: 'block',
      host: 'hostsblock.test',
    });
    expect(rules[0]?.source).toContain('hostsblock.test');
  });

  it('ignores hosts-file rules with non-blocking IPs', () => {
    expect(parseRules(['1.2.3.4 hosts.test'])).toHaveLength(0);
  });

  it('parses multiple lists in one call', () => {
    const rules = parseRules(['||one.test^', '||two.test^', '||three.test^']);
    expect(rules.map((rule) => rule.pattern)).toEqual([
      '||one.test^',
      '||two.test^',
      '||three.test^',
    ]);
  });
});
