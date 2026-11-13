// Minimal mock of `next/server` for offline tests. NOT the real Next.js: it mirrors the two behaviours the middleware uses.
// Real NextResponse.next() marks a pass-through with the `x-middleware-next: 1` response header; NextRequest adds `nextUrl`.
export class NextRequest extends Request {
  get nextUrl() { return new URL(this.url); }
}
export class NextResponse extends Response {
  static next() { return new NextResponse(null, { headers: { "x-middleware-next": "1" } }); }
}
