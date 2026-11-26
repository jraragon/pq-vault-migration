# Deviations from the registered protocol (pre-registration v1.2, OSF p6ugk)

Every deviation after the freeze is logged here with date, reason and the analyses it
affects. The registered document is not edited.

## DEV-001 -- 2026-11-21 23:55 (Europe/Madrid) -- aborted native E2 session

- What happened: the first main-campaign session on the native client
  (`main_native_open_20261121_235330`) was started with the laptop's network still on;
  the protocol requires the network to be disconnected (Section 6, desktop controls).
- Action: the operator noticed it and stopped the session with Ctrl+C after the warm-up
  block, one measured block and part of a second. The session is discarded as a whole and
  repeated from scratch under the protocol. Its files are kept, unanalysed, in
  `results/aborted/` for transparency.
- Blindness: the decision was taken on the protocol violation alone, before any of its
  data were looked at; the data of the aborted session were not opened or analysed.
- Analyses affected: none (the repeated session replaces it).

## DEV-002 -- 2026-11-21 23:59 (Europe/Madrid) -- second aborted native session

- What happened: the repeated native session was started with a Chrome tab and the
  Windows Snipping Tool open; the protocol requires background applications to be closed.
- Action: stopped by the operator shortly after it started; every `main_native_*` folder it
  produced is moved, unanalysed, to `results/aborted/`, and the campaign is started again.
  From here on, `native/scripts/preflight.sh` is run before each launch on the laptop; it
  lists network adapters that are up and applications with a visible window, and the
  session is launched only after it prints PREFLIGHT OK.
- Blindness: decided on the protocol violation alone; the data were not opened.
- Analyses affected: none.

## DEV-003 -- 2026-11-22 -- native session metadata; Windows update after the native sessions

- Native main campaign: six complete sessions (E2 open; E3 keygen, encap, decap, load,
  rewrap), 2026-11-22 00:06--01:37, 11 blocks x 7 configurations each, selftest passed in
  each. Pre-flight check at 00:05: Wi-Fi disconnected; only host-only virtual adapters up
  (Hyper-V, WSL, VirtualBox); windows open: the terminal and the Realtek Audio Console.
- Metadata gap: the run script's records of the power plan and of running processes are
  empty (`power_scheme=`, `processes_running=0`), because MSYS2 rewrote the options of
  `powercfg` and `tasklist` as paths. The power plan and open windows were checked by the
  pre-flight step instead. Script fixed (path conversion disabled) for later sessions.
- Windows update: Windows Update restarted the laptop at 05:20 to finish an update, about
  four hours after the last native run. Its event log shows no update activity between the
  start of the first session (00:06) and the end of the last (01:37); the last event before
  them was a Defender definition update at 23:50. The OS build after the restart is
  10.0.26300.10075; the native sessions ran on the earlier build of the same release
  (26300, from `uname`). The browser sessions on the laptop therefore run on a later build
  than the native sessions. Windows Update is paused until the campaign ends.
- Analyses affected: none of the confirmatory tests, which compare configurations within a
  platform; comparisons across the laptop's platforms (native versus browsers) are
  descriptive and are reported with this note.

## DEV-004 -- 2026-11-22 -- changes to the run tooling after the freeze

Files listed in the freeze manifest that changed after the freeze, none of which changes
what is measured, how it is timed, or how it is analysed:
- `native/scripts/run_pilot.sh` (MSYS2 path conversion disabled, DEV-003);
  `native/scripts/preflight.sh` added (DEV-002).
- `web/server.py`, `web/src/main.js`, `web/public/index.html`, `web/public/p15bench.js`:
  an "all" option runs E2 and the five E3 operations as six consecutive sessions, each with
  its own folder, warm-up block and selftest, so that a browser campaign needs no operator
  action between sessions. Each session is identical to one launched by hand.
  `web/src/core.js` (cryptography and timing) is unchanged.
- Checked end to end in headless Chrome (six sessions, six selftests, chained in order).

## DEV-005 -- 2026-11-22 09:45 (Europe/Madrid) -- Chrome campaign stopped by the OLED pixel-refresh animation

- What happened: during the first Chrome desktop campaign (started about 09:08; E2 finished,
  E3 keygen in progress) a full-screen moving animation covered the page and disappeared on
  mouse movement. The Windows screen saver was already set to "(none)". The cause is the
  vendor feature ASUS OLED Care "Pixel Refresh" (MyASUS > Device settings > Audio and
  visual), enabled by factory default, which starts a full-screen pixel-refresh animation
  after 30 minutes without user input. The protocol requires the page to stay in the
  foreground: a covered page can be treated by the browser as hidden, with throttled timers
  and a lower process priority, and the animation itself uses CPU and GPU, which would bias
  the timings.
- Action: the campaign is stopped and its folders (`main_web_chrome-desktop_*` of that
  morning) are moved, unanalysed, to `results/aborted/`. "Pixel Refresh" is disabled for the
  rest of the measurement campaign (re-enabled afterwards); MyASUS required a brief network
  connection to change it, made with Chrome and Firefox closed and Windows Update paused,
  after which airplane mode was restored. Screen brightness is set to minimum during browser
  campaigns. The Chrome campaign is repeated from the start, with the preflight check and the
  5-minute idle period. "Pixel Shift" (one-pixel image displacement) cannot be disabled and
  stays on.
- Native sessions of the night before: the animation very probably also ran during them,
  since they lasted about 90 minutes without input. A native process has no page-visibility
  throttling, but the animation adds some background CPU/GPU load. The native data are kept:
  their quality checks (between-run coefficient of variation of 0.1--0.4 % in E2, no flagged
  runs) show no sign of disturbance, and the same condition applied to all configurations
  within each block.
- Blindness: decided on the protocol violation alone; the data were not opened.
- Analyses affected: none.

## DEV-006 -- 2026-11-22 12:09 (Europe/Madrid) -- Chrome load session stalled; run-page watchdog added

- What happened: in the repeated Chrome desktop campaign (started 10:00:03, after the
  5-minute idle period; `results/main_web_chrome-desktop_*_20261122_10000[34]`), the sessions
  open, keygen, encap and decap completed (77 runs each, selftest passed, no gap between runs
  longer than the run itself). The load session stopped at 12:09:10 after 5 runs of its
  warm-up block: when the operator returned, the page showed the initial setup form, i.e. the
  script bundle of the page for run 6 had not started. The rewrap session never started (its folder, with only the plan and selftest, is also moved to `results/aborted/`).
  The Windows System and Application logs show no sleep, wake or power event between 11:55
  and 16:35 (a licensing event at 12:09:27 and a restore point at 12:14 are later and
  unrelated to page loading). The exact cause could not be determined: the server did not log
  static-file requests or their errors. At 16:26 the operator pressed F5 about ten times while
  trying to raise the screen brightness; each press reloaded the page and re-posted run
  r00p6, which appears ten times in `runs.csv` of that session.
- Action: the stalled load session is moved, unanalysed, to `results/aborted/`. The four
  complete sessions are kept. The load and rewrap sessions are repeated in Chrome (same
  browser version, same settings, 5-minute idle period first); each session is an independent
  plan with its own selftest and warm-up block, so no other session is affected.
- Harness change (measurement code unchanged; `web/src/core.js`, the native and Android
  sources are identical to the registered freeze d364f6f):
  (1) a start watchdog in `index.html`: a run page that has not started its timed run within
  90 s reloads itself, at most 5 times, and the reload is recorded in the session's
  `events.txt`; it cannot fire during a timed run;
  (2) the wait for the browser's client-hints version string is bounded to 3 s;
  (3) the server keeps the first result of a run and logs, but ignores, any repeated post
  (so an accidental reload cannot overwrite or duplicate data);
  (4) the server now logs run-page loads and all request errors, with timestamps.
  Tested locally with headless Chrome: a full chained session, a forced bundle-load failure
  (recovered by one watchdog reload) and a duplicate post. The Firefox desktop and Chrome
  Android campaigns use this harness from the start.
- Blindness: decided on the protocol and run logs alone; no timing data were opened.
- Analyses affected: none. Any session with a watchdog reload is reported in the descriptive
  tables; the reloaded run is a fresh page load, as every run is by design.

- Outcome: load and rewrap repeated on 2026-11-22 (`main_web_chrome-desktop_load_20261122_170510`,
  `main_web_chrome-desktop_rewrap_20261122_172133`), 77 runs each, selftest passed, no watchdog
  reload, same Chrome version (158.0.8127.37) as the other four sessions. Windows automatic
  maintenance was moved to 11:00 (outside all remaining campaigns) and its wake-up option disabled.

## DEV-007 -- 2026-11-23 (Europe/Madrid) -- Android app: 20 s cool-down; runner safeguards; keygen timing probe

Decided before any main-campaign data from the phone were collected.

- Cool-down: the pre-registration (Section "Mobile controls") sets 60 s between runs for the
  native Android app and 20 s for the mobile browser (D-018). The app campaign uses 20 s.
  Reason: practical (the phone is the operator's personal device, and 60 s over six sessions
  of 77 runs, with slow RSA key generation, would keep it out of use for 10--12 hours), with
  empirical support: on the same phone, the mobile-browser pilot with 20 s kept the battery at
  34.2--34.5 C, and the app pilot (60 s) stayed at 29--34.5 C. The safeguards are unchanged:
  battery temperature is recorded before every run, runs starting above 40 C are flagged, and
  the analysis reports flagged runs. Sessions may be run on different days (each session is an
  independent plan with its own selftest and warm-up block, as on the laptop).
- Runner safeguards (harness only; the app's measurement code is unchanged since the freeze):
  the per-run wait was a fixed 600 s, after which the script silently continued; it is now
  `TIMEOUT_S` (default 4 h) and a run that exceeds it aborts the session, keeping its files.
  The wall-clock duration of every run is logged in `durations.csv`.
- Timing probe: to schedule the keygen session, one `KIND=probe` block of keygen (7 runs,
  20 timed operations, warm-up 5) is run on the phone; `WARMUP` other than 50 is refused for
  any other kind. Only wall-clock durations are read; the probe is not analysed and is kept in
  `results/probe_android_keygen_*` for completeness. The same was done on 2026-11-24 for
  Chrome on Android, through the page (`kind` pilot, label `chrome-android-probe`, 2 blocks of
  keygen, 10 timed operations, warm-up 50; `results/pilot_web_chrome-android-probe_keygen_*`):
  the run end times and the mean time per key generation were read to schedule the session
  (about 0.35--0.5 s per RSA-3072 key, under 1 ms per ML-KEM key); not analysed.
- Analyses affected: none (sensitivity: temperature-flagged runs, as pre-registered).

## DEV-008 -- 2026-11-23 12:50 (Europe/Madrid) -- Android app: encap session started twice

- What happened: the encap session of the app campaign completed at 11:38--12:15
  (`main_android_encap_20261123_113814`; 77 runs, selftest passed). Not having pushed it, the
  operator started it again at 12:50. The second session was stopped after its selftest and
  first runs, the app force-stopped, and its folder (no run files copied from the phone) moved
  to `results/aborted/main_android_encap_20261123_125027`.
- Rule applied: the first complete session of an operation is the valid one; the decision
  depends only on the order of sessions, not on their data.
- Safeguard: the Android runner and the browser server now refuse to start a `KIND=main` session for an operation
  that already has a session folder outside `results/aborted/` (override `FORCE=1` only under a
  logged deviation).
- Analyses affected: none.

## DEV-009 -- 2026-11-23 23:37 (Europe/Madrid) -- Android app keygen: phone rotated during a warm-up run

- What happened: during run r00p1 (RSA-3072 keygen, warm-up block 00) of
  `main_android_keygen_20261123_233301`, the operator moved the phone and the screen rotated
  two or three times. On Android a rotation recreates the activity, and each recreation started
  the same run again in a parallel thread of the same process, so r00p1 was measured under
  contention (it took 786 s against a median of 681 s for the other RSA and hybrid keygen runs).
  The operator then locked rotation and lowered the screen brightness, still within block 00,
  and did not touch the phone again.
- Effect: none on the analysis. Block 00 is a warm-up block, discarded by design. The runner
  force-stops the app after each run, which ended the parallel copies; every later run started
  in a fresh process (the next run, r00p2, took 723 s; measured blocks 656--711 s).
- The session completed at about 06:17 on 2026-11-24 (77 runs, selftest passed, battery
  31.4--37.2 C, no run above 40 C). It is kept.
- Safeguard: rotation lock is set on the phone for all remaining mobile sessions. The app
  campaign is complete, so the app is not rebuilt; the browser does not restart a page on
  rotation.

## DEV-010 -- 2026-11-24 (Europe/Madrid) -- Exploratory validation (D-026): implementation details fixed before running

Written before any validation run on the laptop. The pre-registration fixes the sample, the
factors, the comparison and the adequacy band; these details were left to the implementation.

- Code: `native/src/p15_arch.c` (new); it includes the frozen `p15_a1.c` unchanged (with its
  `main` renamed), so every primitive is the measured one. Driver `native/scripts/run_validation.sh`;
  sample and run order `analysis/make_validation_sample.py` -> `data/validation_sample.csv`,
  `data/validation_plan.csv` (rank-based deciles of n_total among accounts with n_total <= 1000,
  ties broken by account id; 3 accounts per decile and then the order of the 240 runs, both
  from `default_rng(15)`; sum of n_total 6,570, median 136, maximum 974). Analysis
  `analysis/validation_analysis.py`.
- Account tree, deterministic per account: the n_f top-level items are folders (the
  pre-registered A1b upper bound); of the other n_total - n_f nodes, min(round(0.8 n_total),
  n_total - n_f) are files and the rest subfolders; each node takes a parent uniformly among the
  folders created before it. c (children of the top-level folders) is read from the tree.
- Migration runs in an unlocked session: old tree keys and file content keys are in memory, no
  decapsulation under the old suite is timed, and holders' target-suite credentials exist
  (holder key generation excluded, as in the model). This matches the model, which counts only
  K, E and W.
- A2: node private keys are stored as RFC 9935 PKCS#8 (seed form) wrapped with AES-256-KWP
  (RFC 5649) under a key derived (HKDF, as in A1) from the node packet; top-level nodes
  encapsulate to an account share key pair, whose private key is wrapped under packets to each
  holder. The share key pair is one key generation per account that the model does not count;
  it is part of what the validation measures. A3: scrypt (N = 2^15, r = 8, p = 1) master key
  and AES-KW node keys; its migration to a public-key suite does nothing.
- Prediction: K_ops K_s + E_ops E_s + W_ops W with the native E3 unit costs (median over the
  measured blocks of the run medians; keygen and encap in seed form, rewrap pooled), and the
  tree's actual counts. Bytes: measured ciphertexts, public keys and stored (wrapped) private
  keys against the analytic sizes; the PKCS#8 and KWP framing of stored private keys is the
  expected deviation.
- Each run verifies, untimed, that a holder opens the migrated account (A1, A1b: root or shared
  folder and its children; A2: from the share down to one file's content key), and aborts
  otherwise. `p15_arch check` runs every architecture and suite on small accounts, with
  verification, before the session.
- Tested on the development machine (Linux build of OpenSSL 4.1.0) on two sampled accounts;
  those test runs were deleted and are not data.
- Outcome (2026-11-24): session `results/main_validation_20261124_104838`, 10:50--11:42, 240 of
  240 runs, every run verified after migration, selftest and `p15_arch check` passed, all runs on
  logical CPU 2 (efficiency class 1, high priority), commit 87ba518, clean tree. Formatting note:
  on Windows the header line of `runs.csv` is repeated before every run (a file opened for append
  reports position 0) and the last field, the CPU-pin description, contains commas;
  `validation_analysis.load_runs` skips the repeated headers and keeps that field whole. No value
  is affected.

## DEV-011 -- 2026-11-25 (Europe/Madrid) -- Browser re-wrap cost W below the timer resolution

Found while reading the results of the registered analysis, after all data were in; recorded
here because it qualifies a registered estimate. No analysis, verdict or data file is changed.

- The pre-registration states that the fastest median operation lasts more than 400 us, so that
  the browser timer resolution (5 us in Chrome, 20 us in Firefox, cross-origin isolated) is
  negligible. That holds for E2, which it was written for, but not for the E3 re-wrap W (one
  AES-KW wrap): about 7 us natively. In the browsers the per-operation samples of W are
  multiples of the timer step: Chrome desktop 5 us (62 % of samples), 10 us (24 %), 0 (12 %);
  Firefox 20 us (84 %), 0 and 40 us (6 and 4 %); Chrome on Android 15--35 us in steps of 5.
  The registered estimate of W (mean over blocks of the run medians) is therefore one timer step
  in Chrome desktop (5 us) and Firefox (20 us); on Chrome Android (20 us) it is a few steps.
- Effect: W enters H4.1 (naive cost n_total W), H3.1 (A1 and A1b re-wraps, a minor term) and X1
  (q = E_s / W). The A1 speed-up S = (n_total W + n_h E_s)/(n_f W + n_h E_s) increases with W, so
  an overestimated W overstates S.
- Exploratory sensitivity (not a verdict): median speed-up recomputed with W at the mean of the
  raw samples and at the native W (7.2 us). Every refuted H4.1 cell of a post-quantum suite in a
  browser stays below 10 (largest: 3.3). The two supported RSA-3072 cells (Firefox 11.5,
  Chrome Android 10.1) fall to 6.6 and 5.5 with the native W; they are reported as dependent on
  an operation shorter than the timer step. X1 values of q in the browsers are reported with the
  same qualification. H3.1 verdicts do not change under either alternative.
- The registered verdicts are reported unchanged; the paper states this limitation.
