// Mutation check for GP-11: inject a defect into the compiled TypeScript core and require the
// vector runner to fail. Usage (from repo root, after `npm test` built typescript/dist-test):
//   node scripts/mutation-test.mjs
import { cpSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ts = join(root, "typescript");
const tmp = join(ts, ".mut");
const TARGET = "security.js";
const MUTATIONS = [
  ["MIN_SECRET_BYTES = 16", "MIN_SECRET_BYTES = 8", "secret length"],
  ["`csrf|${nonce}|${context}`", "`csrf|${nonce}`", "context binding"],
  ["const NONCE = /^[0-9a-f]{32}$/;", "const NONCE = /^[0-9a-fA-F]{32}$/;", "nonce case"],
  ["if (!NONCE.test(nonce) || !SIG.test(sig))", "if (!SIG.test(sig))", "nonce format on verify"],
  ['["X-Frame-Options", "DENY"]', '["X-Frame-Options", "SAMEORIGIN"]', "frame default"],
  ["asciiLower(n) === asciiLower(name)", "n === name", "case-insensitive override"],
  ["out[i] = [out[i][0], v];", "out[i] = [name, v];", "canonical name kept"],
  ["const BAD_VALUE = /[\\u0000-\\u0008\\u000a-\\u001f\\u007f]/;", "const BAD_VALUE = /[\\u0000]/;", "header injection"],
  ["const BAD_SOURCE = /[\\u0000-\\u0020\\u007f;,]/;", "const BAD_SOURCE = /[\\u0000-\\u0020\\u007f,]/;", "csp semicolon injection"],
  ['parts.join("; ")', 'parts.join(";")', "csp separator"],
  ['"\'": "&#39;"', '"\'": "\'"', "apostrophe escaping"],
  ["const UNSAFE_CHAR = /[\\u0000-\\u0020\\u007f\\\\]/;", "const UNSAFE_CHAR = /[\\u0000-\\u001f]/;", "backslash and space"],
  ['!s.startsWith("//")', "true", "protocol-relative"],
  ["/^https?:\\/\\/([^/?#]*)/i", "/^https?:\\/\\/([^/?#]*)/", "scheme case-insensitive"],
  ["allowed.includes(asciiLower(host))", "allowed.some((h) => asciiLower(host).endsWith(h))", "exact host match"],
  ["/^:[0-9]{1,5}$/", "/^:[0-9]*$/", "port digits"],
  ["int(\"minLength\", 12, 1)", "int(\"minLength\", 8, 1)", "default min length"],
  ["/[!-/:-@[-`{-~]/", "/[!-/]/", "symbol class"],
  ["if (run > maxRepeat)", "if (run >= maxRepeat)", "repeat limit"],
  ["Array.from(u).length >= 3", "Array.from(u).length >= 1", "short user input"],
  ["const allowed = count < limit;", "const allowed = count <= limit;", "fixed window limit"],
  ["const windowStart = t - (t % windowMs);", "const windowStart = t;", "window alignment"],
  ["updatedAt = tokens === capacity ? t : updatedAt + intervals * interval;", "updatedAt = t;", "partial interval kept"],
  ["Math.ceil((cost - tokens) / refill)", "Math.floor((cost - tokens) / refill)", "retry rounding"],
  ["Math.min(capacity, tokens + intervals * refill)", "tokens + intervals * refill", "bucket capacity"],
];

const src = readFileSync(join(ts, "dist-test", "src", TARGET), "utf8");
let survived = 0;
for (const [find, repl, label] of MUTATIONS) {
  const count = src.split(find).length - 1;
  if (count === 0) { console.log(`SKIP     ${label}: pattern not found`); survived++; continue; }
  rmSync(tmp, { recursive: true, force: true });
  cpSync(join(ts, "dist-test"), tmp, { recursive: true });
  writeFileSync(join(tmp, "src", TARGET), src.split(find).join(repl));
  const r = spawnSync(process.execPath, ["--test", join(tmp, "test", "vectors.test.js")], { encoding: "utf8" });
  const killed = r.status !== 0;
  if (!killed) survived++;
  console.log(`${killed ? "KILLED  " : "SURVIVED"} ${label}`);
}
rmSync(tmp, { recursive: true, force: true });
console.log(`\n${MUTATIONS.length - survived}/${MUTATIONS.length} mutants killed`);
process.exit(survived === 0 ? 0 : 1);
