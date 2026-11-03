import { describe, expect, it, vi, afterEach } from 'vite-plus/test';
import { BadRequestException } from '@nestjs/common';
import { AdblockService } from './adblock.service.js';
import type { CheckRequest, CompileSafariRequest } from './types.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('AdblockService', () => {
  it('blocks a URL matched by custom rules', async () => {
    const service = new AdblockService();
    const response = await service.check({
      url: 'https://ads.example.com/pixel',
      custom_rules: ['||ads.example.com^'],
    });
    expect(response).toEqual({
      blocked: true,
      rule_matched: '||ads.example.com^',
    });
  });

  it('reports no block when nothing matches', async () => {
    const service = new AdblockService();
    const response = await service.check({
      url: 'https://ok.example.com/',
      custom_rules: ['||ads.example.com^'],
    });
    expect(response).toEqual({ blocked: false });
  });

  it('rejects a missing url', async () => {
    const service = new AdblockService();
    await expect(service.check({} as CheckRequest)).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });

  it('rejects an unparseable url', async () => {
    const service = new AdblockService();
    await expect(
      service.check({ url: 'not a url at all', custom_rules: ['||x.test^'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects non-string list arrays', async () => {
    const service = new AdblockService();
    await expect(
      service.check({
        url: 'https://x.test/',
        lists: [123] as unknown as string[],
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects more than 20 remote lists', async () => {
    const service = new AdblockService();
    const lists = Array.from(
      { length: 21 },
      (_, index) => `https://lists.test/${index}.txt`,
    );
    await expect(
      service.check({ url: 'https://x.test/', lists }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects non-http(s) list urls', async () => {
    const service = new AdblockService();
    await expect(
      service.check({ url: 'https://x.test/', lists: ['file:///etc/passwd'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('tolerates failing list downloads', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('network down')),
    );
    const service = new AdblockService();
    const response = await service.check({
      url: 'https://ads.example.com/',
      lists: ['https://lists.test/f.txt'],
      custom_rules: ['||ads.example.com^'],
    });
    expect(response.blocked).toBe(true);
  });

  it('tolerates non-ok list downloads', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue({ ok: false, status: 404, text: async () => '' }),
    );
    const service = new AdblockService();
    const response = await service.check({
      url: 'https://ads.example.com/',
      lists: ['https://lists.test/missing.txt'],
      custom_rules: ['||ads.example.com^'],
    });
    expect(response.blocked).toBe(true);
  });

  it('matches rules from downloaded lists', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => '||from-list.test^\n',
      }),
    );
    const service = new AdblockService();
    const response = await service.check({
      url: 'https://sub.from-list.test/x',
      lists: ['https://lists.test/f.txt'],
    });
    expect(response).toEqual({
      blocked: true,
      rule_matched: '||from-list.test^',
    });
  });

  it('compiles Safari content blocker JSON', async () => {
    const service = new AdblockService();
    const rules = await service.compileSafari({
      custom_rules: ['||ads.test^', '@@||ok.test^'],
    } satisfies CompileSafariRequest);
    expect(rules).toEqual([
      {
        trigger: { 'url-filter': expect.stringContaining('ads') },
        action: { type: 'block' },
      },
      {
        trigger: { 'url-filter': expect.stringContaining('ok') },
        action: { type: 'ignore-previous-rules' },
      },
    ]);
  });

  it('rejects a missing body', async () => {
    const service = new AdblockService();
    await expect(
      service.check(undefined as unknown as CheckRequest),
    ).rejects.toBeInstanceOf(BadRequestException);
  });
});
