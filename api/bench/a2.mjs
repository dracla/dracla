// A2: does the enforcer's check path fit in the Workers Free CPU limit?
//
// Free allows 10 ms CPU per invocation. CPU excludes I/O wait, so awaiting
// GitHub is free — what counts is signing, hashing, and parsing. Design §9
// names RS256 token minting and commit-listing parse as the two candidates,
// with KV token caching as the mitigation. This measures both.

import { commitListing, coverageShard, webhookBody } from "./fixtures.mjs";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

function ms(fn, iters) {
  // Warm up so we measure steady state, not first-call JIT.
  for (let i = 0; i < Math.min(iters, 5); i++) fn();
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) fn();
  const t1 = process.hrtime.bigint();
  return Number(t1 - t0) / 1e6 / iters;
}

async function msAsync(fn, iters) {
  for (let i = 0; i < Math.min(iters, 5); i++) await fn();
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) await fn();
  const t1 = process.hrtime.bigint();
  return Number(t1 - t0) / 1e6 / iters;
}

const row = (label, v, note = "") =>
  console.log("  " + label.padEnd(46) + v.toFixed(3).padStart(8) + " ms   " + note);

console.log("\nA2 — enforcer check path CPU (Workers Free limit: 10 ms)\n");

// --- 1. RS256: the GitHub App JWT -----------------------------------------
const kp = await subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true, ["sign", "verify"]);
const pkcs8 = await subtle.exportKey("pkcs8", kp.privateKey);

const claim = enc.encode(JSON.stringify({
  iat: 1755500000, exp: 1755500600, iss: "123456" }));

console.log("1. Installation token minting (RS256)");
const importMs = await msAsync(async () => {
  await subtle.importKey("pkcs8", pkcs8,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}, 200);
row("importKey (cold, per isolate)", importMs);

const signMs = await msAsync(async () => {
  await subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, claim);
}, 200);
row("sign (warm key)", signMs);
row("cold path: import + sign", importMs + signMs, "<- no KV cache");
row("warm path: sign only", signMs, "<- module-scope key");
row("cached path: neither", 0, "<- KV-cached token, §9");

// --- 2. Webhook HMAC ------------------------------------------------------
console.log("\n2. Webhook signature verification");
const hmacKey = await subtle.importKey("raw", enc.encode("a".repeat(40)),
  { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
const body = enc.encode(webhookBody());
row("HMAC-SHA256 over body", await msAsync(async () => {
  await subtle.sign("HMAC", hmacKey, body);
}, 500));

// --- 3. Parsing -----------------------------------------------------------
console.log("\n3. JSON parsing");
for (const n of [10, 50, 100, 250]) {
  const s = commitListing(n);
  row(`commit listing, ${String(n).padStart(3)} commits (${(s.length/1024).toFixed(0)} KB)`,
      ms(() => JSON.parse(s), 100));
}
const shard = coverageShard(500);
row(`coverage shard, 500 users (${(shard.length/1024).toFixed(0)} KB)`,
    ms(() => JSON.parse(shard), 200));
row("webhook body (0.4 KB)", ms(() => JSON.parse(webhookBody()), 2000));

// --- 4. Subject resolution ------------------------------------------------
console.log("\n4. Subject resolution (§6.3)");
const trailer = /^Co-authored-by:\s*.*<([^>]+)>/gim;
for (const n of [100, 250]) {
  const parsed = JSON.parse(commitListing(n));
  row(`resolve ${n} commits: authors + trailer scan`, ms(() => {
    const subjects = new Set();
    for (const c of parsed) {
      if (c.author?.id) subjects.add(c.author.id);
      const m = c.commit.message.matchAll(trailer);
      for (const hit of m) {
        const em = hit[1];
        const plus = em.indexOf("+");
        if (em.endsWith("@users.noreply.github.com") && plus > 0)
          subjects.add(Number(em.slice(0, plus)));
      }
    }
    return subjects.size;
  }, 100));
}

// --- 5. Whole path --------------------------------------------------------
console.log("\n5. End-to-end check path (CPU only, I/O excluded)");
for (const [label, n, cached] of [
  ["typical PR (10 commits), token cached", 10, true],
  ["large PR (100 commits), token cached", 100, true],
  ["large PR (100 commits), cold key", 100, false],
  ["worst case (250 commits), cold key", 250, false],
]) {
  const listing = commitListing(n);
  const total = await msAsync(async () => {
    await subtle.sign("HMAC", hmacKey, body);          // verify webhook
    JSON.parse(webhookBody());                          // parse event
    if (!cached) {
      const k = await subtle.importKey("pkcs8", pkcs8,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
      await subtle.sign("RSASSA-PKCS1-v1_5", k, claim); // mint JWT
    }
    const commits = JSON.parse(listing);                // parse commits
    const subjects = new Set();
    for (const c of commits) if (c.author?.id) subjects.add(c.author.id);
    JSON.parse(shard);                                  // parse coverage shard
    JSON.stringify({ conclusion: "success", output: { title: "CLA satisfied" } });
    return subjects.size;
  }, 50);
  const verdict = total < 10 ? "OK" : "OVER LIMIT";
  row(label, total, `<- ${verdict} (${(total / 10 * 100).toFixed(0)}% of budget)`);
}
console.log();
