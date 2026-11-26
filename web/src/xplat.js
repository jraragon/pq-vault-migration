// Cross-platform interchange (D-023): export accounts created here, open accounts created elsewhere.
// Usage: node src/xplat.js export DIR  |  node src/xplat.js open FILE...
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SUITES, createAccount, openAccount } from './core.js';

const hx = (b) => (b && b.length ? Buffer.from(b).toString('hex') : '-');
const unhex = (h) => (h === '-' ? new Uint8Array(0) : Uint8Array.from(Buffer.from(h, 'hex')));
const [cmd, ...args] = process.argv.slice(2);
if (cmd === 'export') {
  for (const s of Object.keys(SUITES)) for (const f of ['seed', 'expanded']) {
    if (s === 'rsa3072' && f === 'expanded') continue;
    const a = await createAccount(s, f, 7, 1), fn = s === 'rsa3072' ? 'na' : f;
    const lines = ['impl noble', `suite ${s}`, `format ${fn}`, `cred ${hx(a.cred)}`, `rsa_pub ${hx(a.pub.rsaPubDer)}`,
      `pkg ${hx(a.pkg)}`, `root ${hx(a.root)}`, ...a.children.map((c) => `child ${hx(c)}`)];
    writeFileSync(join(args[0], `noble_${s}_${fn}.txt`), lines.join('\n') + '\n');
  }
} else if (cmd === 'open') {
  let bad = 0;
  for (const file of args) {
    const kv = readFileSync(file, 'utf8').trim().split('\n').map((l) => l.trim().split(' '));
    const get = (k) => kv.find((x) => x[0] === k)?.[1];
    const fn = get('format');
    const a = { suiteName: get('suite'), fmt: fn === 'expanded' ? 'expanded' : 'seed', cred: unhex(get('cred')),
      pub: { rsaPubDer: unhex(get('rsa_pub')) }, pkg: unhex(get('pkg')),
      children: kv.filter((x) => x[0] === 'child').map((x) => unhex(x[1])) };
    let ok = false;
    try {
      const root = new Uint8Array(await crypto.subtle.exportKey('raw', await openAccount(a, 1)));
      ok = Buffer.from(root).toString('hex') === get('root');
    } catch { ok = false; }
    bad += !ok;
    console.log(`  ${ok ? 'ok:  ' : 'FAIL:'}  ${get('impl').padEnd(12)} -> noble: ${a.suiteName.padEnd(9)} ${fn.padEnd(8)} (${a.children.length} children)`);
  }
  console.log(`Cross-platform open on noble/WebCrypto: ${args.length} files, ${bad} failures`);
  process.exit(bad ? 1 : 0);
}
