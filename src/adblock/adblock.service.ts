import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { isSupportedListUrl, loadLists, MAX_LISTS } from './lists.js';
import { buildRuleSet, matchUrl } from './matcher.js';
import { parseRules } from './parser.js';
import { compileSafariRules } from './safari-compiler.js';
import type {
  CheckRequest,
  CheckResponse,
  CompileSafariRequest,
  SafariRule,
} from './types.js';

type BodyLike = Partial<CheckRequest & CompileSafariRequest>;

@Injectable()
export class AdblockService {
  private readonly logger = new Logger(AdblockService.name);

  /** `POST /api/check` — loads the lists and tests one URL against them. */
  async check(request: CheckRequest): Promise<CheckResponse> {
    const body = this.asBody(request);

    if (typeof body.url !== 'string' || body.url.trim() === '') {
      throw new BadRequestException('`url` must be a non-empty string');
    }

    const rules = await this.collectRules(body);
    const result = matchUrl(body.url, buildRuleSet(rules));
    if (result === null)
      throw new BadRequestException('`url` is not a valid URL');

    return result.blocked && result.rule !== undefined
      ? { blocked: true, rule_matched: result.rule.source }
      : { blocked: false };
  }

  /** `POST /api/compile-safari` — loads the lists and emits Safari JSON. */
  async compileSafari(request: CompileSafariRequest): Promise<SafariRule[]> {
    const rules = await this.collectRules(this.asBody(request));
    return compileSafariRules(rules);
  }

  /** Request bodies are untrusted input: normalize before touching them. */
  private asBody(request: unknown): BodyLike {
    if (typeof request !== 'object' || request === null) return {};
    return request as BodyLike;
  }

  private async collectRules(
    body: BodyLike,
  ): Promise<ReturnType<typeof parseRules>> {
    const lists = this.stringArray(body.lists, 'lists');
    const customRules = this.stringArray(body.custom_rules, 'custom_rules');

    if (lists.length > MAX_LISTS) {
      throw new BadRequestException(
        `At most ${MAX_LISTS} filter lists per request`,
      );
    }
    for (const list of lists) {
      if (!isSupportedListUrl(list)) {
        throw new BadRequestException(
          `Only http(s) filter list URLs are supported, got: ${list}`,
        );
      }
    }

    const { texts, failed } = await loadLists(lists);
    if (failed.length > 0) {
      this.logger.warn(
        `could not load ${failed.length} filter list(s): ${failed.join(', ')}`,
      );
    }

    return parseRules([...texts, customRules.join('\n')]);
  }

  private stringArray(value: unknown, field: string): string[] {
    if (value === undefined || value === null) return [];
    if (
      !Array.isArray(value) ||
      value.some((item) => typeof item !== 'string')
    ) {
      throw new BadRequestException(`\`${field}\` must be an array of strings`);
    }
    return value as string[];
  }
}
