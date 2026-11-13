// Test-only: resolve `next/server` to a small stub so the tests run offline with no install.
import { registerHooks } from "node:module";
registerHooks({
  resolve(spec, ctx, next) {
    if (spec === "next/server") return { url: new URL("./next-server-stub.mjs", import.meta.url).href, shortCircuit: true };
    return next(spec, ctx);
  },
});
