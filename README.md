# honeypot-trap

One-file Next.js middleware that plants a hidden link in your HTML pages and bans any client that follows it. MIT, no dependencies, one file to copy: [`middleware.ts`](middleware.ts).

A person never sees or tabs to the link (off-screen, `aria-hidden`, `tabindex="-1"`), and compliant crawlers are told by `robots.txt` to stay away. Whatever requests the trap path anyway is recorded (IP + user-agent) and every later request from that IP gets a `403` (or a tarpit delay, then `403`) until the ban expires.

**What it is not.** It catches clients that follow links without honouring `robots.txt`; clients that don't parse HTML links or that rotate IPs are not caught. It is not a WAF or a bot-detection service, and this repo makes no claim about any named bot beyond what the tests below show.

## Quickstart

1. Copy `middleware.ts` to your Next.js project root (or `src/`). If you already have a middleware, call `createHoneypot(...)` from yours.
2. Edit `OPTIONS` at the bottom of the file and the `config.matcher` (the default skips `_next/static`, `_next/image` and `favicon.ico`).
3. Add the trap to `public/robots.txt` so good crawlers skip it (`robotsTxtRule()` prints the lines):

   ```
   User-agent: *
   Disallow: /trap/
   ```
4. Deploy (`vercel deploy`). View source on any HTML page and look for `data-honeypot="1"` just before `</body>`.

### Options

| option | default | meaning |
|---|---|---|
| `trapPath` | `/trap` | prefix of the trap; the link points at `<trapPath>/archive`. Matches whole path segments (`/trapdoor` is not the trap) |
| `banTtlSeconds` | `86400` | how long a ban lasts |
| `response` / `tarpitMs` | `"403"` / `5000` | `"tarpit"` waits `tarpitMs` before the 403 (you pay for that wall-clock time on the edge) |
| `allowBots` | Googlebot, bingbot | UA patterns that are never banned or blocked |
| `verifyBot(ip, ua)` | none | your proof for an allowlisted UA; return `false` and the client is treated as ordinary |
| `store` | in-memory | where bans live, see below |
| `onEvent(e)` | none | log hook: `trap-hit`, `banned-block`, `injected`, `allowlisted`, `no-ip`, `store-error`, `injection-failed` |
| `inject` | `true` | `false` = don't touch pages (bring your own link with `honeypotHtml()`, e.g. in your layout) |
| `ipHeader` | `x-forwarded-for` | header holding the client IP (first entry used, then `x-real-ip`) |

### Allowlist and reverse DNS

`allowBots` matches the User-Agent string, and anyone can send `Googlebot/2.1` as their UA. A UA match alone is therefore a convenience, not proof. The documented way to verify Googlebot / Bingbot is a reverse DNS lookup of the IP followed by a forward lookup that must return the same IP. Edge runtimes have no DNS API, so this file does not do it for you: pass `verifyBot` (for example a call to your own DNS-over-HTTPS check, cached) and a spoofed UA is treated like any other client. The test suite shows that path with a stub function; it does not ship a DNS checker.

### Storage

The default `MemoryStore` is per edge instance: bans are not shared between regions or instances and vanish on a cold start. For a shared ban list use any Upstash Redis / Vercel KV client through `kvStore` (the file imports no client, you install yours):

```ts
import { Redis } from "@upstash/redis";
import { createHoneypot, kvStore } from "./middleware";   // or inline in middleware.ts
const handler = createHoneypot({ store: kvStore(Redis.fromEnv()), banTtlSeconds: 3600 });
```

`kvStore` only needs `get(key)` and `set(key, value, { ex })`. The tests exercise it with a fake client; it has not been run against a live Upstash database by this repo. If the store throws, the request is served (fail open) and a `store-error` event is emitted.

### How injection works, and its cost

Next.js middleware runs before the page renders and cannot edit the page body itself. This file therefore re-requests the same URL from the edge (with an `x-honeypot-subrequest: 1` header so the second pass is a plain pass-through), injects the link into the HTML and returns that. Consequences: **each HTML page view costs one extra same-origin request**, only `GET` requests that accept `text/html` and look like pages (no file extension) are touched, non-HTML responses are returned as they came, and if the subrequest fails the page is served without the link. If that cost is not acceptable, set `inject: false` and place `honeypotHtml()` in your layout yourself; the trap and bans work the same. Inline `style` on the link needs a CSP that allows inline styles, otherwise the link may become visible.

## Tests and saved runs

Node's built-in runner, no install, offline. Node 22.18+ (runs `.ts` natively):

```
npm test            # = node --import ./test/register.mjs --test --test-reporter=spec test/
npm run simulate    # regenerates samples/request-log.jsonl and samples/injected-page.html
```

`next/server` is replaced by a ~10-line stub (`test/next-server-stub.mjs`), and the tests call the handler with mock `NextRequest` objects. **This is not a run on a real Next.js server or on Vercel**; the code uses only Web-standard APIs, which is what the edge runtime provides, but that has not been measured here.

Saved from the actual run (`samples/test-output.txt`): **27 tests, 27 pass, 0 fail**. They cover injection, invisible-link attributes, idempotence, non-HTML and non-GET pass-through, no fetch loop, trap hit (403 + IP/UA recorded), ban of that IP only, TTL expiry, store eviction, exact path-segment matching, custom trap path, Googlebot/Bingbot allowlist, spoofed-UA rejection through `verifyBot`, tarpit, log-hook and store failures, `inject:false`, missing IP, and the `kvStore` adapter.

Simulated request log (`samples/request-log.jsonl`, fake clock, ban TTL 600 s, produced by `npm run simulate`):

```
2026-11-13T10:00:00.000Z  203.0.113.10    /              -> 200 (link injected)   # human loads home page
2026-11-13T10:00:00.000Z  203.0.113.10    /api/items     -> 200 (pass-through)   # human fetches JSON
2026-11-13T10:00:00.000Z  66.249.66.1     /              -> 200 (pass-through)   # Googlebot UA loads home page
2026-11-13T10:00:00.000Z  198.51.100.23   /trap/archive  -> 403   # crawler follows hidden link
2026-11-13T10:00:05.000Z  198.51.100.23   /pricing       -> 403   # same crawler, next page
2026-11-13T10:00:05.000Z  203.0.113.10    /pricing       -> 200 (link injected)   # human on another IP
2026-11-13T10:05:05.000Z  198.51.100.23   /pricing       -> 403   # crawler, 305 s later (ban 600 s)
2026-11-13T10:10:06.000Z  198.51.100.23   /pricing       -> 200 (link injected)   # crawler, 606 s later (expired)
```

The "crawler" there is a scripted request, not a real bot; the log shows the logic, not field results. The page it produced is in `samples/injected-page.html`.

## Other things I publish

Unrelated to this repo (there is no paid version of honeypot-trap): pay-per-event tools on Apify, for example the [SEC Form 4 insider cluster scanner](https://apify.com/johnveds15/sec-form4-insider-clusters) ($0.0004 per Form 4 filing parsed, $0.02 per insider cluster detected; price read from the Apify API on 2026-11-13), and source-code packs for agent work on Gumroad: the [Agent-Turn Delta-Debugger CLI](https://vedovino.gumroad.com/l/zdwyic) ($25) and the [Agent log policy checker](https://vedovino.gumroad.com/l/agent-log-policy-checker) ($19), prices as listed on 2026-11-13.

## License

MIT, see [LICENSE](LICENSE). Not published to npm: it is a file you copy.
