// Historical A2 lower bound measured inside workerd, the Workers runtime.
// Same operations as bench/a2.mjs, so the two numbers are comparable.
import { commitListing, coverageShard, webhookBody } from "./fixtures.mjs";

const subtle = crypto.subtle;
const enc = new TextEncoder();

async function msAsync(fn, iters) {
  for (let i = 0; i < 5; i++) await fn();
  const t0 = Date.now();
  let spins = 0;
  // Date.now() is coarse in Workers; loop until the clock actually advances.
  while (Date.now() === t0) { await fn(); spins++; }
  const t1 = Date.now();
  for (let i = 0; i < iters; i++) await fn();
  const t2 = Date.now();
  return (t2 - t1) / iters;
}

export default {
  async fetch() {
    const out = [];
    const kp = await subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true, ["sign", "verify"]);
    const pkcs8 = await subtle.exportKey("pkcs8", kp.privateKey);
    const claim = enc.encode(JSON.stringify({ iat: 1, exp: 2, iss: "1" }));
    const hmacKey = await subtle.importKey("raw", enc.encode("a".repeat(40)),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const body = enc.encode(webhookBody());
    const shard = coverageShard(500);

    out.push(["RS256 sign (warm key)",
      await msAsync(async () => subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, claim), 200)]);
    out.push(["HMAC-SHA256 webhook verify",
      await msAsync(async () => subtle.sign("HMAC", hmacKey, body), 500)]);

    for (const n of [10, 100, 250]) {
      const s = commitListing(n);
      out.push([`JSON.parse ${n} commits (${(s.length/1024)|0} KB)`,
        await msAsync(async () => JSON.parse(s), 200)]);
    }

    for (const [label, n, warmToken] of [
      ["e2e typical PR (10), warm-isolate token", 10, true],
      ["e2e large PR (100), warm-isolate token", 100, true],
      ["e2e large PR (100), cold key", 100, false],
      ["e2e worst case (250), cold key", 250, false],
    ]) {
      const listing = commitListing(n);
      out.push([label, await msAsync(async () => {
        await subtle.sign("HMAC", hmacKey, body);
        JSON.parse(webhookBody());
        if (!warmToken) {
          const k = await subtle.importKey("pkcs8", pkcs8,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
          await subtle.sign("RSASSA-PKCS1-v1_5", k, claim);
        }
        const commits = JSON.parse(listing);
        const subjects = new Set();
        for (const c of commits) if (c.author?.id) subjects.add(c.author.id);
        JSON.parse(shard);
        JSON.stringify({ conclusion: "success" });
        return subjects.size;
      }, 50)]);
    }

    const lines = out.map(([l, v]) =>
      "  " + l.padEnd(40) + v.toFixed(3).padStart(8) + " ms" +
      (l.startsWith("e2e") ? `   ${v < 10 ? "LEGACY UNDER" : "LEGACY OVER"} (${(v/10*100).toFixed(0)}% of budget)` : ""));
    return new Response(
      "A2 historical lower bound in workerd (Workers Free CPU limit: 10 ms)\n\n" +
      lines.join("\n") +
      "\n\nRevision-13 A2 remains open; this fixture is not release evidence.\n");
  },
};
