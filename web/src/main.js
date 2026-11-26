// P15 browser client: UI, selftest and pilot runner.
// Each run of a pilot is executed in a freshly loaded page (?plan=ID&i=k); the
// page posts its CSV to the local server and then navigates to the next run.
import { selftest, sizes, bench, timerResolutionUs } from './core.js';

const $ = (id) => document.getElementById(id);
const out = (s) => { $('out').textContent += s + '\n'; };
const params = new URLSearchParams(location.search);

function guessLabel() {
  const ua = navigator.userAgent, mobile = /Android|Mobile/.test(ua);
  const br = /Firefox\//.test(ua) ? 'firefox' : /Edg\//.test(ua) ? 'edge' : /Chrome\//.test(ua) ? 'chrome' : 'browser';
  return `${br}-${mobile ? 'android' : 'desktop'}`;
}
// Full browser version: Chromium reduces the user-agent string to "157.0.0.0", so ask
// User-Agent Client Hints (Chromium only); Firefox keeps its full version in the UA.
let fullVersion = 'na';
async function initFullVersion() {
  try {
    // Bounded wait: a pending client-hints promise must not stall a run page (DEV-006).
    const h = await Promise.race([
      navigator.userAgentData.getHighEntropyValues(['fullVersionList', 'platformVersion']),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))]);
    fullVersion = h.fullVersionList.map((b) => `${b.brand} ${b.version}`).join('; ') + ` | platform ${h.platformVersion}`;
  } catch { fullVersion = 'na'; }
}
function envLines(res) {
  return [
    `user_agent=${navigator.userAgent}`,
    `browser_full_version=${fullVersion}`,
    `cross_origin_isolated=${globalThis.crossOriginIsolated}`,
    `timer_resolution_us=${res.toFixed(3)}`,
    `hardware_concurrency=${navigator.hardwareConcurrency}`,
    `noble_post_quantum=0.7.1 noble_hashes=2.4.0`,
  ];
}

async function runPlanStep(planId, i) {
  const plan = await (await fetch(`/api/plan/${planId}`)).json();
  const run = plan.runs[i];
  $('status').textContent = `[${plan.op}] Run ${i + 1}/${plan.runs.length}: ${run.id}${run.id.startsWith('r00') ? ' (warm-up block)' : ''}. Do not touch the device.`;
  if (i === 0) {
    // Every session (one per operation) starts with its own selftest (D-034).
    $('status').textContent = `Session ${plan.op}: selftest...`;
    let log = '';
    const fails = await selftest((l) => { log += l + '\n'; });
    const r = await (await fetch(`/api/selftest/${planId}`, { method: 'POST', body: log })).json();
    if (fails || !r.ok) { $('status').textContent = `SELFTEST FAILED -- session ${plan.op} not run.`; return; }
    $('status').textContent = `Session ${plan.op}: starting in ${plan.start_delay_s} s. Do not touch the device.`;
    await new Promise((r) => setTimeout(r, plan.start_delay_s * 1000));
  }
  window.__p15running = true;  // disarms the start watchdog in index.html (DEV-006)
  if (params.has('r')) {
    await fetch(`/api/event/${planId}`, { method: 'POST',
      body: `watchdog reload ${params.get('r')} of run page i=${i} (${run.id}); run started normally` });
  }
  const res = timerResolutionUs();
  const ns = await bench(run.suite, run.format, plan.op, plan.iters, plan.warmup, plan.nf);
  const lines = ['# p15_web bench', ...envLines(res).map((l) => '# ' + l),
    `# suite=${run.suite} format=${run.format} op=${plan.op} iters=${plan.iters} warmup=${plan.warmup} nf=${plan.nf}`,
    `# run_id=${run.id}`, '# time_source=performance.now', 'run_id,suite,format,op,iter,ns'];
  for (let k = 0; k < ns.length; k++) lines.push(`${run.id},${run.suite},${run.format},${plan.op},${k},${ns[k]}`);
  await fetch(`/api/result/${planId}/${run.id}`, { method: 'POST', body: lines.join('\n') + '\n' });
  if (i + 1 >= plan.runs.length) {
    await fetch(`/api/done/${planId}`, { method: 'POST' });
    if (plan.next) {
      $('status').textContent = `Session ${plan.op} finished; next session in ${plan.cooldown_s} s. Do not touch the device.`;
      setTimeout(() => location.replace(`?plan=${plan.next}&i=0`), plan.cooldown_s * 1000);
      return;
    }
    $('status').textContent = `Finished: ${plan.runs.length} runs saved by the server in ${plan.dir}. ALL SESSIONS DONE.`;
    return;
  }
  let left = plan.cooldown_s;
  const tick = () => {
    $('status').textContent = `Run ${i + 1}/${plan.runs.length} saved. Next run in ${left} s. Do not touch the device.`;
    if (left-- <= 0) location.replace(`?plan=${planId}&i=${i + 1}`); else setTimeout(tick, 1000);
  };
  tick();
}

async function startPilot() {
  $('out').textContent = '';
  $('status').textContent = 'Selftest before the session...';
  let log = '';
  const fails = await selftest((l) => { log += l + '\n'; out(l); });
  if (fails) { $('status').textContent = 'SELFTEST FAILED -- session not started.'; return; }
  const body = {
    selftest: log,
    label: $('label').value.trim(), kind: $('kind').value, op: $('op').value, reps: +$('reps').value, iters: +$('iters').value,
    cooldown_s: +$('cooldown').value, env: envLines(timerResolutionUs()),
  };
  const r = await (await fetch('/api/plan', { method: 'POST', body: JSON.stringify(body) })).json();
  if (r.error) { $('status').textContent = 'NOT STARTED: ' + r.error; return; }
  location.replace(`?plan=${r.id}&i=0`);
}

async function main() {
  if (params.has('plan')) $('setup').hidden = true;
  await initFullVersion();
  if (params.has('plan')) return runPlanStep(params.get('plan'), +params.get('i'));
  $('label').value = guessLabel();
  $('cooldown').value = /Android|Mobile/.test(navigator.userAgent) ? 20 : 2;  // D-018
  const res = timerResolutionUs();
  envLines(res).forEach(out);
  if (!globalThis.crossOriginIsolated) out('WARNING: page is not cross-origin isolated; timer resolution is coarse. Open it through server.py.');
  $('selftest').onclick = async () => {
    $('out').textContent = ''; envLines(res).forEach(out); out('');
    await selftest(out); out('\n' + await sizes());
  };
  $('start').onclick = startPilot;
}
main().catch((e) => { $('status').textContent = 'ERROR: ' + e; console.error(e); });
