#!/usr/bin/env python3
"""
P15 -- local server for the browser client (Python standard library only).

Serves web/public with cross-origin isolation headers (COOP/COEP), so that
performance.now() has its finest resolution, and receives the CSV of every run.
Binds to 127.0.0.1 only. For the phone: `adb reverse tcp:8015 tcp:8015`, then
open http://localhost:8015 in the phone's browser.

Usage (from web/):  python server.py [PORT]
"""
import json, os, random, subprocess, sys, datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8015
HERE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(HERE, "public")
RESULTS = os.path.normpath(os.path.join(HERE, "..", "results"))
CONFIGS = [("rsa3072", "na"), ("mlkem768", "seed"), ("mlkem768", "expanded"), ("mlkem1024", "seed"),
           ("mlkem1024", "expanded"), ("hybrid", "seed"), ("hybrid", "expanded")]
PLANS = {}
OPS = ("open", "keygen", "encap", "decap", "load", "rewrap")


def git_commit():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True, text=True).stdout.strip()
    except Exception:
        return "unknown"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=PUBLIC, **kw)

    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt, *args):  # quieter console: API calls and run pages only
        first = str(args[0] if args else "")
        if "/api/" in first or "?plan=" in first:
            sys.stderr.write("%s %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), fmt % args))

    def log_error(self, fmt, *args):  # always shown (the default goes through the filter above)
        sys.stderr.write("%s ERROR %s %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), self.path, fmt % args))

    def _json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n)

    def _make_plan(self, req, label, kind, op):
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pid = f"{label}_{op}_{stamp}"
        d = os.path.join(RESULTS, f"{kind}_web_{label}_{op}_{stamp}")
        os.makedirs(d, exist_ok=True)
        runs = []
        # Block 00 is a warm-up block, discarded by the analysis (D-016).
        for rep in range(0, int(req["reps"]) + 1):
            order = CONFIGS[:]
            random.shuffle(order)
            for pos, (s, f) in enumerate(order, 1):
                runs.append({"id": f"r{rep:02d}p{pos}_{s}_{f}", "suite": s, "format": f})
        plan = {"id": pid, "dir": os.path.relpath(d, os.path.join(HERE, "..")), "runs": runs,
                "iters": int(req["iters"]), "warmup": 50, "nf": 7, "op": op,
                "cooldown_s": int(req["cooldown_s"]), "start_delay_s": 10, "next": None}
        PLANS[pid] = plan
        with open(os.path.join(d, "meta.txt"), "w") as fh:
            fh.write(f"date_utc={datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
            fh.write(f"git_commit={git_commit()}\nlabel={label}\nkind={kind}\n")
            fh.write(f"reps={req['reps']} iters={plan['iters']} warmup=50 nf=7 op={op} cooldown_s={plan['cooldown_s']}\n")
            for line in req.get("env", []):
                fh.write(line + "\n")
        with open(os.path.join(d, "selftest.txt"), "w") as fh:
            fh.write(req.get("selftest", ""))
        self._save_plan(plan)
        print(f"Plan {pid}: {len(runs)} runs -> {plan['dir']}")
        return pid

    def _event(self, plan, text):
        # Protocol events of a session (watchdog reloads, ignored duplicates): events.txt.
        line = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')},{text.strip()}"
        with open(os.path.join(HERE, "..", plan["dir"], "events.txt"), "a") as fh:
            fh.write(line + "\n")
        print(f"  EVENT {plan['id']}: {text.strip()}")

    def _save_plan(self, plan):
        with open(os.path.join(HERE, "..", plan["dir"], "plan.json"), "w") as fh:
            json.dump(plan, fh, indent=1)

    def do_GET(self):
        if self.path.startswith("/api/plan/"):
            pid = self.path.split("/")[3]
            return self._json(PLANS[pid]) if pid in PLANS else self._json({"error": "unknown plan"}, 404)
        return super().do_GET()

    def do_POST(self):
        parts = self.path.split("/")
        if self.path == "/api/plan":
            req = json.loads(self._body())
            label = "".join(c for c in req["label"] if c.isalnum() or c in "-_") or "browser"
            kind = "main" if req.get("kind") == "main" else "pilot"
            op = req.get("op", "open")
            ops = list(OPS) if op == "all" else [op]
            if any(o not in OPS for o in ops):
                return self._json({"error": "bad op"}, 400)
            if kind == "main" and not req.get("force"):
                # Refuse to repeat a main session that already exists outside results/aborted (DEV-008).
                done = [o for o in ops if any(n.startswith(f"main_web_{label}_{o}_") for n in os.listdir(RESULTS))]
                if done:
                    return self._json({"error": f"main session already exists for {label}: {', '.join(done)}; "
                                                 "move it to results/aborted first if a deviation says so"}, 409)
            if "SELFTEST PASSED" not in req.get("selftest", ""):
                return self._json({"error": "selftest did not pass"}, 400)
            # One session (plan, folder, warm-up block) per operation; "all" chains E2 and
            # the five E3 operations, each session starting with its own selftest (D-034).
            pids = [self._make_plan(req, label, kind, o) for o in ops]
            for a, b in zip(pids, pids[1:]):
                PLANS[a]["next"] = b
                self._save_plan(PLANS[a])
            return self._json({"id": pids[0], "chain": pids})
        if len(parts) >= 4 and parts[2] == "selftest":
            plan = PLANS.get(parts[3])
            if not plan:
                return self._json({"error": "unknown plan"}, 404)
            text = self._body().decode("utf-8", "replace")
            with open(os.path.join(HERE, "..", plan["dir"], "selftest.txt"), "w") as fh:
                fh.write(text)
            ok = "SELFTEST PASSED" in text
            print(f"Selftest for {parts[3]}: {'passed' if ok else 'FAILED'}")
            return self._json({"ok": ok})
        if len(parts) >= 5 and parts[2] == "result":
            pid, rid = parts[3], parts[4]
            plan = PLANS.get(pid)
            if not plan or "/" in rid or ".." in rid:
                return self._json({"error": "bad request"}, 400)
            body = self._body()
            path = os.path.join(HERE, "..", plan["dir"], rid + ".csv")
            if os.path.exists(path):
                # A run is kept once: a repeated post (manual reload of a finished run) is
                # logged and ignored, so it can neither overwrite nor duplicate (DEV-006).
                self._event(plan, f"duplicate result for {rid} ignored")
                return self._json({"ok": True, "duplicate": True})
            with open(path, "wb") as fh:
                fh.write(body)
            # End time of the run (local clock, same as the temperature logger).
            with open(os.path.join(HERE, "..", plan["dir"], "runs.csv"), "a") as fh:
                if fh.tell() == 0:
                    fh.write("run_id,end_local\n")
                fh.write(f"{rid},{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\n")
            print(f"  saved {rid}")
            return self._json({"ok": True})
        if len(parts) >= 4 and parts[2] == "event":
            plan = PLANS.get(parts[3])
            if not plan:
                return self._json({"error": "unknown plan"}, 404)
            self._event(plan, self._body().decode("utf-8", "replace")[:500])
            return self._json({"ok": True})
        if len(parts) >= 4 and parts[2] == "done":
            print(f"Plan {parts[3]} finished.")
            return self._json({"ok": True})
        return self._json({"error": "not found"}, 404)


if __name__ == "__main__":
    print(f"P15 web server on http://localhost:{PORT}  (results in {RESULTS})")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
