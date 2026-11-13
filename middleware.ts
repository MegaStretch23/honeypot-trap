// honeypot-trap: one-file Next.js middleware that plants a hidden link, bans whoever follows it.
// MIT. No dependencies. Uses only Web-standard APIs (Request, Response, Headers, fetch, setTimeout)
// plus `next/server`, which your Next.js app already has.
//
// Copy this file to the project root (or src/) as `middleware.ts`, edit OPTIONS and `config.matcher`, deploy.
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// ---------------------------------------------------------------- types
export interface Ban { ip: string; ua: string; path: string; at: number; until: number }

/** Anything with these two methods works. `ttlSeconds` is how long the ban lasts. */
export interface Store {
  get(key: string): Promise<Ban | null | undefined> | Ban | null | undefined;
  set(key: string, value: Ban, ttlSeconds: number): Promise<unknown> | unknown;
}

export interface HoneypotEvent {
  type: "trap-hit" | "banned-block" | "injected" | "allowlisted" | "no-ip" | "store-error" | "injection-failed";
  ip?: string; ua?: string; path?: string; at: number; detail?: string;
}

export interface HoneypotConfig {
  /** Prefix of the trap. The hidden link points at `${trapPath}/archive`. Default "/trap". */
  trapPath?: string;
  /** Ban length in seconds. Default 86400 (24 h). */
  banTtlSeconds?: number;
  /** What a banned client (and the trap hit itself) receives. "403" = immediate 403. "tarpit" = wait `tarpitMs`, then 403. Default "403". */
  response?: "403" | "tarpit";
  tarpitMs?: number;
  /** User-Agents treated as good bots: never banned, never blocked. UA strings are spoofable; see `verifyBot`. */
  allowBots?: RegExp[];
  /** Optional proof for an allowlisted UA, e.g. a reverse-DNS check you run yourself. Return false = treat as an ordinary client. */
  verifyBot?: (ip: string | undefined, ua: string) => boolean | Promise<boolean>;
  /** Ban storage. Default: in-memory (per edge instance). See `kvStore` for Upstash / Vercel KV. */
  store?: Store;
  /** Log hook, called for every event. Exceptions inside it are swallowed. */
  onEvent?: (e: HoneypotEvent) => void;
  /** Inject the hidden link into HTML responses. Default true. Needs one extra same-origin fetch per HTML page (see README). */
  inject?: boolean;
  /** Header that carries the client IP. Default "x-forwarded-for" (first entry); falls back to x-real-ip. */
  ipHeader?: string;
  /** Test seams. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  fetchOrigin?: (req: Request) => Promise<Response>;
}

// ---------------------------------------------------------------- stores
/** In-memory store. Per edge instance (not shared across regions/instances) and lost on cold start. Bounded to `maxEntries`. */
export class MemoryStore implements Store {
  private m = new Map<string, Ban>();
  private maxEntries: number;
  private now: () => number;
  constructor(maxEntries = 10000, now: () => number = Date.now) { this.maxEntries = maxEntries; this.now = now; }
  get(key: string): Ban | null {
    const v = this.m.get(key);
    if (!v) return null;
    if (v.until <= this.now()) { this.m.delete(key); return null; }
    return v;
  }
  set(key: string, value: Ban): void {
    this.m.delete(key);
    this.m.set(key, value);
    while (this.m.size > this.maxEntries) this.m.delete(this.m.keys().next().value as string);
  }
  get size(): number { return this.m.size; }
}

/** Adapter for Upstash Redis / Vercel KV style clients: `get(key)` and `set(key, value, { ex })`. The client is yours; this file imports nothing. */
export function kvStore(client: { get(k: string): Promise<unknown>; set(k: string, v: unknown, o: { ex: number }): Promise<unknown> }): Store {
  return {
    async get(key) {
      const raw = await client.get(key);
      if (raw == null) return null;
      return (typeof raw === "string" ? JSON.parse(raw) : raw) as Ban;
    },
    async set(key, value, ttlSeconds) { await client.set(key, JSON.stringify(value), { ex: Math.max(1, Math.ceil(ttlSeconds)) }); },
  };
}

// ---------------------------------------------------------------- helpers
export const SUBREQUEST_HEADER = "x-honeypot-subrequest";
const MARK = 'data-honeypot="1"';

export function normalizeTrap(p: string): string {
  const t = "/" + p.replace(/^\/+|\/+$/g, "");
  return t === "/" ? "/trap" : t;
}

/** The markup that gets injected. Invisible to people (off-screen, aria-hidden, not focusable), hidden from search engines by robots.txt. */
export function honeypotHtml(trapPath = "/trap"): string {
  return `<a ${MARK} href="${normalizeTrap(trapPath)}/archive" aria-hidden="true" tabindex="-1" rel="nofollow noindex" style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden">archive</a>`;
}

/** Lines to add to robots.txt so compliant crawlers never visit the trap. */
export function robotsTxtRule(trapPath = "/trap"): string {
  return `User-agent: *\nDisallow: ${normalizeTrap(trapPath)}/\n`;
}

export function injectInto(html: string, trapPath = "/trap"): string {
  if (html.includes(MARK)) return html;
  const tag = honeypotHtml(trapPath);
  const i = html.toLowerCase().lastIndexOf("</body");
  return i === -1 ? html + tag : html.slice(0, i) + tag + html.slice(i);
}

export function clientIp(h: Headers, ipHeader = "x-forwarded-for"): string | undefined {
  const raw = h.get(ipHeader) ?? h.get("x-real-ip");
  const first = raw?.split(",")[0]?.trim();
  return first ? first : undefined;
}

// ---------------------------------------------------------------- core
export function createHoneypot(cfg: HoneypotConfig = {}) {
  const trap = normalizeTrap(cfg.trapPath ?? "/trap");
  const ttl = cfg.banTtlSeconds ?? 86400;
  const now = cfg.now ?? Date.now;
  const store = cfg.store ?? new MemoryStore(10000, now);
  const allow = cfg.allowBots ?? [/\bGooglebot\b/i, /\bbingbot\b/i];
  const sleep = cfg.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const doFetch = cfg.fetchOrigin ?? ((r: Request) => fetch(r));
  const emit = (e: Omit<HoneypotEvent, "at">) => { try { cfg.onEvent?.({ ...e, at: now() }); } catch { /* a broken log hook must not break the site */ } };
  const key = (ip: string) => `honeypot:ban:${ip}`;

  async function deny(): Promise<Response> {
    if (cfg.response === "tarpit") await sleep(cfg.tarpitMs ?? 5000);
    return new NextResponse("Forbidden", { status: 403, headers: { "content-type": "text/plain", "cache-control": "no-store" } });
  }

  async function handle(request: NextRequest | Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const ua = request.headers.get("user-agent") ?? "";
    const ip = clientIp(request.headers, cfg.ipHeader);

    // 1. good bots: UA match, and the optional proof if you gave one
    if (allow.some((re) => re.test(ua)) && (!cfg.verifyBot || (await cfg.verifyBot(ip, ua)))) {
      emit({ type: "allowlisted", ip, ua, path });
      return NextResponse.next();
    }

    // 2. already banned? (runs for every request, including ones that carry the subrequest header)
    if (ip) {
      try {
        const ban = await store.get(key(ip));
        if (ban && ban.until > now()) { emit({ type: "banned-block", ip, ua, path }); return deny(); }
      } catch (err) { emit({ type: "store-error", ip, detail: String(err) }); }
    }

    // 3. the trap itself
    if (path === trap || path.startsWith(trap + "/")) {
      if (!ip) { emit({ type: "no-ip", ua, path }); return deny(); }
      const at = now();
      try { await store.set(key(ip), { ip, ua, path, at, until: at + ttl * 1000 }, ttl); }
      catch (err) { emit({ type: "store-error", ip, detail: String(err) }); }
      emit({ type: "trap-hit", ip, ua, path });
      return deny();
    }

    // 4. inject into HTML pages
    const wantsHtml = (request.headers.get("accept") ?? "").includes("text/html");
    const isAsset = /\.[a-z0-9]{1,8}$/i.test(path);
    if (cfg.inject === false || request.method !== "GET" || !wantsHtml || isAsset || request.headers.has(SUBREQUEST_HEADER)) {
      return NextResponse.next();
    }
    try {
      const h = new Headers(request.headers);
      h.set(SUBREQUEST_HEADER, "1");
      const up = await doFetch(new Request(request.url, { method: "GET", headers: h, redirect: "manual" }));
      if (!(up.headers.get("content-type") ?? "").toLowerCase().includes("text/html")) return up;
      const body = injectInto(await up.text(), trap);
      const out = new Headers(up.headers);
      for (const k of ["content-length", "content-encoding", "transfer-encoding"]) out.delete(k);
      emit({ type: "injected", ip, ua, path });
      return new NextResponse(body, { status: up.status, statusText: up.statusText, headers: out });
    } catch (err) {
      emit({ type: "injection-failed", ip, path, detail: String(err) });
      return NextResponse.next();   // fail open: the page is served without the link
    }
  }
  return handle;
}

// ---------------------------------------------------------------- your settings
const OPTIONS: HoneypotConfig = {
  trapPath: "/trap",
  banTtlSeconds: 60 * 60 * 24,
  response: "403",
  // onEvent: (e) => console.log(JSON.stringify(e)),
};

const handler = createHoneypot(OPTIONS);
export function middleware(request: NextRequest) { return handler(request); }

// Edit: skip static assets and Next internals. robots.txt must stay reachable.
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
