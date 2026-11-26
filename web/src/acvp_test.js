// FIPS 203 ACVP vectors (testdata/acvp_mlkem.txt) through the measurement loading path (D-023).
// Usage: node src/acvp_test.js ../testdata/acvp_mlkem.txt
import { readFileSync } from 'node:fs';
import { loadCredential, decap, mlkemCredential } from './core.js';

const hex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
let n = 0, bad = 0;
for (const line of readFileSync(process.argv[2], 'utf8').split('\n')) {
  if (!line || line.startsWith('#')) continue;
  const [kind, suite, a, b, c] = line.trim().split(' ');
  let ok;
  if (kind === 'kg') ok = eq((await loadCredential(suite, 'seed', mlkemCredential(suite, 'seed', hex(a)))).ml, hex(b));
  else ok = eq(await decap(suite, await loadCredential(suite, 'expanded', mlkemCredential(suite, 'expanded', hex(a))), hex(b)), hex(c));
  n++; if (!ok) { bad++; console.log(`  FAIL: ${kind} ${suite} vector ${n}`); }
}
console.log(`ACVP ML-KEM (@noble/post-quantum 0.7.1): ${n} vectors, ${bad} failures`);
process.exit(bad || !n ? 1 : 0);
