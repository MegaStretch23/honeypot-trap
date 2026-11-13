import { test } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { createHoneypot, MemoryStore, kvStore, honeypotHtml, robotsTxtRule, injectInto, clientIp, normalizeTrap, SUBREQUEST_HEADER } from "../middleware.ts";

const PAGE = "<!doctype html><html><head><title>t</title></head><body><h1>Hello</h1></body></html>";
const HUMAN = "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0";

function req(path: string, o: { ip?: string; ua?: string; accept?: string; method?: string; headers?: Record<string, string> } = {}) {
  const h: Record<string, string> = { "user-agent": o.ua ?? HUMAN, accept: o.accept ?? "text/html,application/xhtml+xml", ...(o.headers ?? {}) };
  if (o.ip !== null) h["x-forwarded-for"] = o.ip ?? "203.0.113.7";
  return new NextRequest("https://example.com" + path, { method: o.method ?? "GET", headers: h });
}
function rig(extra: Record<string, unknown> = {}) {
  const clock = { t: 1_000_000 };
  const events: any[] = [];
  const fetched: Request[] = [];
  const hp = createHoneypot({
    now: () => clock.t, sleep: async () => {}, onEvent: (e) => events.push(e),
    fetchOrigin: async (r) => { fetched.push(r); return new Response(PAGE, { status: 200, headers: { "content-type": "text/html; charset=utf-8", "content-length": String(PAGE.length) } }); },
    ...extra,
  });
  return { hp, clock, events, fetched };
}
const isPass = (r: Response) => r.headers.get("x-middleware-next") === "1";

test("injects the hidden link before </body> in an HTML response", async () => {
  const { hp } = rig();
  const r = await hp(req("/"));
  const body = await r.text();
  assert.equal(r.status, 200);
  assert.ok(body.includes('href="/trap/archive"'));
  assert.ok(body.indexOf("data-honeypot") < body.indexOf("</body>"));
  assert.ok(body.startsWith("<!doctype html>") && body.includes("<h1>Hello</h1>"));
});

test("the injected link is invisible and unfocusable: aria-hidden, tabindex=-1, off-screen", () => {
  const html = honeypotHtml("/trap");
  assert.match(html, /aria-hidden="true"/);
  assert.match(html, /tabindex="-1"/);
  assert.match(html, /left:-9999px/);
  assert.match(html, /rel="nofollow noindex"/);
});

test("injection drops stale content-length / content-encoding and keeps the status", async () => {
  const { hp } = rig();
  const r = await hp(req("/x"));
  assert.equal(r.headers.get("content-length"), null);
  assert.equal(r.headers.get("content-encoding"), null);
  assert.match(r.headers.get("content-type")!, /text\/html/);
});

test("injection is idempotent: a page that already has the link is not changed", () => {
  const once = injectInto(PAGE);
  assert.equal(injectInto(once), once);
  assert.equal(once.split("data-honeypot").length - 1, 1);
});

test("a page without </body> gets the link appended", () => {
  assert.ok(injectInto("<p>fragment</p>").endsWith("</a>"));
});

test("non-HTML upstream response (JSON) passes through untouched", async () => {
  const { hp } = rig({ fetchOrigin: async () => new Response('{"a":1}', { headers: { "content-type": "application/json" } }) });
  const r = await hp(req("/api-ish", { accept: "text/html" }));
  assert.equal(await r.text(), '{"a":1}');
});

test("request that does not accept HTML is passed through with no subrequest", async () => {
  const { hp, fetched } = rig();
  const r = await hp(req("/api/data", { accept: "application/json" }));
  assert.ok(isPass(r));
  assert.equal(fetched.length, 0);
});

test("asset-looking paths and non-GET requests are passed through", async () => {
  const { hp, fetched } = rig();
  assert.ok(isPass(await hp(req("/logo.png", { accept: "text/html" }))));
  assert.ok(isPass(await hp(req("/form", { method: "POST" }))));
  assert.equal(fetched.length, 0);
});

test("a request carrying the subrequest header is not injected again (no fetch loop)", async () => {
  const { hp, fetched } = rig();
  const r = await hp(req("/", { headers: { [SUBREQUEST_HEADER]: "1" } }));
  assert.ok(isPass(r));
  assert.equal(fetched.length, 0);
});

test("the subrequest sent to the origin carries the marker header and the client headers", async () => {
  const { hp, fetched } = rig();
  await hp(req("/page", { ip: "198.51.100.4" }));
  assert.equal(fetched.length, 1);
  assert.equal(fetched[0].headers.get(SUBREQUEST_HEADER), "1");
  assert.equal(fetched[0].headers.get("x-forwarded-for"), "198.51.100.4");
});

test("hitting the trap path returns 403 and records IP + user-agent", async () => {
  const store = new MemoryStore(100, () => 1_000_000);
  const { hp, events } = rig({ store });
  const r = await hp(req("/trap/archive", { ip: "192.0.2.50", ua: "scraper/1.0" }));
  assert.equal(r.status, 403);
  const hit = events.find((e) => e.type === "trap-hit");
  assert.deepEqual([hit.ip, hit.ua, hit.path], ["192.0.2.50", "scraper/1.0", "/trap/archive"]);
  const ban = store.get("honeypot:ban:192.0.2.50")!;
  assert.equal(ban.ua, "scraper/1.0");
});

test("after a trap hit, later requests from that IP get 403, other IPs are unaffected", async () => {
  const { hp } = rig();
  await hp(req("/trap/archive", { ip: "192.0.2.50" }));
  assert.equal((await hp(req("/pricing", { ip: "192.0.2.50" }))).status, 403);
  assert.equal((await hp(req("/pricing", { ip: "192.0.2.51" }))).status, 200);
});

test("a ban expires after banTtlSeconds", async () => {
  const { hp, clock } = rig({ banTtlSeconds: 60 });
  await hp(req("/trap/x", { ip: "192.0.2.50" }));
  clock.t += 59_000;
  assert.equal((await hp(req("/", { ip: "192.0.2.50" }))).status, 403);
  clock.t += 2_000;
  assert.equal((await hp(req("/", { ip: "192.0.2.50" }))).status, 200);
});

test("MemoryStore expires entries on read and evicts the oldest past maxEntries", () => {
  const c = { t: 0 };
  const s = new MemoryStore(2, () => c.t);
  const b = (ip: string, until: number) => ({ ip, ua: "", path: "/", at: 0, until });
  s.set("a", b("a", 10)); s.set("b", b("b", 100)); s.set("c", b("c", 100));
  assert.equal(s.get("a"), null);          // evicted (size cap 2)
  assert.ok(s.get("b") && s.get("c"));
  c.t = 100;
  assert.equal(s.get("b"), null);          // expired
});

test("trap prefix matching is exact on path segments: /trapdoor is not the trap", async () => {
  const { hp } = rig();
  assert.equal((await hp(req("/trapdoor", { ip: "192.0.2.60" }))).status, 200);
  assert.equal((await hp(req("/", { ip: "192.0.2.60" }))).status, 200);
  assert.equal((await hp(req("/trap", { ip: "192.0.2.61" }))).status, 403);
});

test("configurable trap path: link, trap and robots rule all follow it", async () => {
  const { hp } = rig({ trapPath: "/internal/wp-admin-backup/" });
  const body = await (await hp(req("/"))).text();
  assert.ok(body.includes('href="/internal/wp-admin-backup/archive"'));
  assert.equal((await hp(req("/internal/wp-admin-backup/archive", { ip: "192.0.2.70" }))).status, 403);
  assert.equal(robotsTxtRule("/internal/wp-admin-backup/"), "User-agent: *\nDisallow: /internal/wp-admin-backup/\n");
  assert.equal(normalizeTrap("trap/"), "/trap");
});

test("allowlisted bot UA (Googlebot, Bingbot) is never banned, even on the trap", async () => {
  const store = new MemoryStore(100, () => 1_000_000);
  const { hp, events } = rig({ store });
  const g = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
  const r = await hp(req("/trap/archive", { ip: "66.249.66.1", ua: g }));
  assert.ok(isPass(r));
  assert.equal(store.get("honeypot:ban:66.249.66.1"), null);
  assert.ok(events.some((e) => e.type === "allowlisted"));
  const b = await hp(req("/trap/archive", { ip: "157.55.39.1", ua: "Mozilla/5.0 (compatible; bingbot/2.0)" }));
  assert.ok(isPass(b));
});

test("verifyBot can reject a spoofed Googlebot UA, which is then treated as an ordinary client", async () => {
  const { hp } = rig({ verifyBot: (ip: string) => ip === "66.249.66.1" });
  const fake = "Googlebot/2.1";
  assert.equal((await hp(req("/trap/archive", { ip: "198.51.100.99", ua: fake }))).status, 403);
  assert.equal((await hp(req("/", { ip: "198.51.100.99", ua: fake }))).status, 403);
  assert.ok(isPass(await hp(req("/trap/archive", { ip: "66.249.66.1", ua: fake }))));
});

test("tarpit mode waits tarpitMs before the 403", async () => {
  const waits: number[] = [];
  const { hp } = rig({ response: "tarpit", tarpitMs: 7000, sleep: async (ms: number) => { waits.push(ms); } });
  const r = await hp(req("/trap/a", { ip: "192.0.2.80" }));
  assert.equal(r.status, 403);
  assert.deepEqual(waits, [7000]);
  await hp(req("/", { ip: "192.0.2.80" }));
  assert.deepEqual(waits, [7000, 7000]);
});

test("log hook receives events and a throwing hook does not break the request", async () => {
  const { hp } = rig({ onEvent: () => { throw new Error("log sink down"); } });
  assert.equal((await hp(req("/trap/a", { ip: "192.0.2.90" }))).status, 403);
});

test("a failing store fails open: the page is served and a store-error event is logged", async () => {
  const events: any[] = [];
  const broken = { get: async () => { throw new Error("kv down"); }, set: async () => { throw new Error("kv down"); } };
  const { hp } = rig({ store: broken, onEvent: (e: any) => events.push(e) });
  assert.equal((await hp(req("/", { ip: "192.0.2.91" }))).status, 200);
  assert.ok(events.some((e) => e.type === "store-error"));
});

test("a failing origin subrequest falls back to pass-through (page still served)", async () => {
  const { hp, events } = rig({ fetchOrigin: async () => { throw new Error("boom"); } });
  assert.ok(isPass(await hp(req("/"))));
  assert.ok(events.some((e) => e.type === "injection-failed"));
});

test("inject:false leaves pages alone but the trap and bans still work", async () => {
  const { hp, fetched } = rig({ inject: false });
  assert.ok(isPass(await hp(req("/"))));
  assert.equal(fetched.length, 0);
  assert.equal((await hp(req("/trap/a", { ip: "192.0.2.92" }))).status, 403);
});

test("no determinable IP: the trap hit gets a 403 but nothing can be recorded", async () => {
  const { hp, events } = rig();
  assert.equal((await hp(req("/trap/a", { ip: null as any }))).status, 403);
  assert.ok(events.some((e) => e.type === "no-ip"));
});

test("the subrequest header does not bypass an existing ban", async () => {
  const { hp } = rig();
  await hp(req("/trap/a", { ip: "192.0.2.93" }));
  assert.equal((await hp(req("/", { ip: "192.0.2.93", headers: { [SUBREQUEST_HEADER]: "1" } }))).status, 403);
});

test("clientIp takes the first x-forwarded-for entry, falls back to x-real-ip, honours ipHeader", () => {
  assert.equal(clientIp(new Headers({ "x-forwarded-for": "1.1.1.1, 2.2.2.2" })), "1.1.1.1");
  assert.equal(clientIp(new Headers({ "x-real-ip": "3.3.3.3" })), "3.3.3.3");
  assert.equal(clientIp(new Headers({ "cf-connecting-ip": "4.4.4.4" }), "cf-connecting-ip"), "4.4.4.4");
  assert.equal(clientIp(new Headers()), undefined);
});

test("kvStore adapter writes JSON with an EX ttl and reads it back (fake Upstash-style client)", async () => {
  const calls: any[] = []; const data = new Map<string, string>();
  const fake = { get: async (k: string) => data.get(k) ?? null, set: async (k: string, v: any, o: any) => { calls.push([k, o]); data.set(k, v); } };
  const { hp } = rig({ store: kvStore(fake), banTtlSeconds: 120 });
  await hp(req("/trap/a", { ip: "192.0.2.94" }));
  assert.deepEqual(calls[0], ["honeypot:ban:192.0.2.94", { ex: 120 }]);
  assert.equal((await hp(req("/", { ip: "192.0.2.94" }))).status, 403);
});
