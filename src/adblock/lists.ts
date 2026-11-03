/**
 * Downloads remote filter lists. Failures are contained per list so one dead
 * URL never fails a whole request.
 */

/** Upper bound of remote lists per request. */
export const MAX_LISTS = 20;

const FETCH_TIMEOUT_MS = 10_000;

export interface LoadedLists {
  /** Text of every list that could be downloaded. */
  texts: string[];
  /** URLs that failed (network error, timeout or non-2xx status). */
  failed: string[];
}

/** Only absolute http(s) URLs are fetched — guards against `file:` and friends. */
export function isSupportedListUrl(raw: string): boolean {
  try {
    const url = new URL(raw);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

/** Fetches all lists in parallel; never rejects. */
export async function loadLists(urls: readonly string[]): Promise<LoadedLists> {
  const results = await Promise.all(
    urls.map(async (url) => {
      try {
        const response = await fetch(url, {
          headers: {
            accept: 'text/plain,application/octet-stream;q=0.9,*/*;q=0.8',
          },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
        if (!response.ok)
          throw new Error(`unexpected status ${response.status}`);
        return await response.text();
      } catch {
        return null;
      }
    }),
  );

  const texts: string[] = [];
  const failed: string[] = [];
  results.forEach((text, index) => {
    if (text === null) failed.push(urls[index]);
    else texts.push(text);
  });
  return { texts, failed };
}
