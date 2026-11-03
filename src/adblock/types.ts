/**
 * Request/response contracts of the NaeroGuard API.
 */

/** Body of `POST /api/check`. */
export interface CheckRequest {
  /** URL to test, e.g. `https://ads.example.com/track`. */
  url: string;
  /** Remote filter lists in plain-text AdGuard/uBlock/ABP syntax. */
  lists?: string[];
  /** Extra rules applied on top of the loaded lists. */
  custom_rules?: string[];
}

/** Response of `POST /api/check`. */
export interface CheckResponse {
  blocked: boolean;
  /** Original filter-list line that matched; only present when `blocked`. */
  rule_matched?: string;
}

/** Body of `POST /api/compile-safari`. */
export interface CompileSafariRequest {
  /** Remote filter lists in plain-text AdGuard/uBlock/ABP syntax. */
  lists?: string[];
  /** Extra rules applied on top of the loaded lists. */
  custom_rules?: string[];
}

/** One entry of Apple's Safari Content Blocker JSON format. */
export interface SafariRule {
  trigger: {
    'url-filter': string;
  };
  action: {
    type: 'block' | 'ignore-previous-rules';
  };
}
