// Runs the real middleware.ts against a scripted sequence of simulated requests (mock NextRequest, fake clock, in-memory store).
// Nothing here talks to a network. Output: samples/request-log.jsonl and samples/injected-page.html
import { writeFileSync } from "node:fs";
import { NextRequest } from "next/server";
import { createHoneypot, MemoryStore } from "../middleware.ts";

const PAGE = "<!doctype html><html><head><title>Shop</title></head><body><h1>Welcome</h1><p>Catalogue below.</p></body></html>";
const clock = { t: Date.UTC(2026, 10, 13, 10, 0, 0) };
const events: any[] = [];
const hp = createHoneypot({
  banTtlSeconds: 600, now: () => clock.t, store: new MemoryStore(1000, () => clock.t), sleep: async () => {},
  onEvent: (e) => events.push(e),
  fetchOrigin: async () => new Response(PAGE, { headers: { "content-type": "text/html" } }),
});
const log: any[] = [];
let page = "";
async function send(label: string, path: string, ip: string, ua: string, accept = "text/html") {
  const r = await hp(new NextRequest("https://example.test" + path, { headers: { "x-forwarded-for": ip, "user-agent": ua, accept } }));
  const body = r.status === 200 && (r.headers.get("content-type") ?? "").includes("html") ? await r.text() : "";
  if (!page && body) page = body;
  log.push({ t: new Date(clock.t).toISOString(), label, ip, ua, path, status: r.status, passthrough: r.headers.get("x-middleware-next") === "1", injected: body.includes("data-honeypot") });
}
const HUMAN = "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0";
await send("human loads home page", "/", "203.0.113.10", HUMAN);
await send("human fetches JSON", "/api/items", "203.0.113.10", HUMAN, "application/json");
await send("Googlebot UA loads home page", "/", "66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
await send("crawler follows hidden link", "/trap/archive", "198.51.100.23", "scraper-sim/1.0");
clock.t += 5_000;
await send("same crawler, next page", "/pricing", "198.51.100.23", "scraper-sim/1.0");
await send("human on another IP", "/pricing", "203.0.113.10", HUMAN);
clock.t += 300_000;
await send("crawler, 305 s later (ban 600 s)", "/pricing", "198.51.100.23", "scraper-sim/1.0");
clock.t += 301_000;
await send("crawler, 606 s later (expired)", "/pricing", "198.51.100.23", "scraper-sim/1.0");
writeFileSync(new URL("./request-log.jsonl", import.meta.url), log.map((l) => JSON.stringify(l)).join("\n") + "\n");
writeFileSync(new URL("./injected-page.html", import.meta.url), page + "\n");
writeFileSync(new URL("./events.jsonl", import.meta.url), events.map((e) => JSON.stringify(e)).join("\n") + "\n");
console.log(log.map((l) => `${l.t}  ${l.ip.padEnd(15)} ${l.path.padEnd(14)} -> ${l.status}${l.injected ? " (link injected)" : ""}${l.passthrough ? " (pass-through)" : ""}   # ${l.label}`).join("\n"));
