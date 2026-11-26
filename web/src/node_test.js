// Test the browser core on Node (WebCrypto is available as globalThis.crypto).
import { selftest, sizes, bench, timerResolutionUs } from './core.js';

const fails = await selftest(console.log);
console.log('\n' + await sizes());
console.log(`\ntimer resolution ~ ${timerResolutionUs().toFixed(3)} us`);
for (const [s, f] of [['rsa3072', 'na'], ['mlkem1024', 'seed'], ['mlkem1024', 'expanded'], ['hybrid', 'seed']]) {
  const ns = Array.from(await bench(s, f, 'open', 200, 20, 7)).sort((a, b) => a - b);
  console.log(`open ${s.padEnd(10)} ${f.padEnd(9)} median ${(ns[100] / 1000).toFixed(1)} us`);
}
process.exit(fails ? 1 : 0);
