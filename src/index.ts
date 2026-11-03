// src/index.ts

export interface CheckRequest {
  url: string;
  lists: string[];
  custom_rules: string[];
}

export interface CheckResponse {
  blocked: boolean;
  rule_matched?: string;
}

// Beispiel für die Logik, die später die Listen verarbeitet
export function handleUrlCheck(req: CheckRequest): CheckResponse {
  // Hier greift später deine Parsing-Logik / der Filter-Check
  const isBlocked = req.custom_rules.some((rule) => req.url.includes(rule));

  return {
    blocked: isBlocked,
    rule_matched: isBlocked ? "Custom Rule Match" : undefined,
  };
}

// Falls du es als Cloudflare Worker deployst:
export default {
  async fetch(request: Request): Promise<Response> {
    if (request.method === "POST") {
      const body: CheckRequest = await request.json();
      const result = handleUrlCheck(body);
      return Response.json(result);
    }
    return new Response("NaeroGuard Core is running.", { status: 200 });
  },
};
