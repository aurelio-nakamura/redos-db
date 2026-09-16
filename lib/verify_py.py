#!/usr/bin/env python3
"""Measured verification of a redos-db entry whose target engine is CPython's `re`.

Reads one catalogue entry as JSON on stdin and prints a JSON verification result
on stdout, in the same shape the Node verifier (lib/verify.js) produces, so the
build/test pipeline can treat JavaScript- and Python-engine entries uniformly.

Each single regex match runs in a *disposable child process* so a genuinely
catastrophic pattern can never wedge the run: if a match exceeds the time budget
the child is SIGKILLed (CPython does not check signals inside the C regex loop,
so terminate() is not enough) and the point is recorded as ">= budget ms". A
benign input must stay fast. From the timing curve we derive an empirical
complexity class and compare it to the entry's declared one. No third-party deps.
"""
import sys, json, re, time
from multiprocessing import Process, Queue

BUDGET_MS = 2000
BENIGN_MAX_MS = 30
BLOWUP_FLOOR_MS = 15  # absolute noise floor; real threshold is 20x the benign time

SIZES = {
    "exponential": [14, 18, 22, 26, 30],
    "cubic": [2000, 4000, 8000, 16000],
    "quadratic": [2500, 5000, 10000, 20000],
}

FLAG_MAP = {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A, "u": re.U}


def compile_flags(flags):
    f = 0
    for ch in (flags or ""):
        if ch in FLAG_MAP:
            f |= FLAG_MAP[ch]
    return f


def _run(pattern, flags, text, q):
    try:
        rx = re.compile(pattern, compile_flags(flags))
    except Exception as e:  # pragma: no cover
        q.put(["err", str(e)])
        return
    start = time.perf_counter()
    try:
        rx.search(text)
    except Exception:
        pass
    q.put(["ok", (time.perf_counter() - start) * 1000.0])


def measure(pattern, flags, text, budget_ms):
    q = Queue()
    p = Process(target=_run, args=(pattern, flags, text, q))
    p.start()
    p.join(budget_ms / 1000.0)
    if p.is_alive():
        p.kill()
        p.join()
        return (budget_ms, True, None)
    try:
        kind, val = q.get(timeout=1)
    except Exception:
        return (budget_ms, True, None)
    if kind == "err":
        return (None, False, val)
    return (val, False, None)


def measure_stable(pattern, flags, text, budget_ms, reps=3):
    runs = []
    for _ in range(reps):
        ms, timed_out, err = measure(pattern, flags, text, budget_ms)
        if err is not None:
            return (None, False, err)
        runs.append((budget_ms, True) if timed_out else (ms, False))
    if any(t for _, t in runs):
        return (budget_ms, True, None)
    xs = sorted(ms for ms, _ in runs)
    return (xs[len(xs) // 2], False, None)


def build_input(attack, n):
    return (attack.get("prefix") or "") + (attack.get("pad") or "") * n + (attack.get("suffix") or "")


def loglog_slope(pts):
    """Least-squares slope of log(ms) vs log(n) over the completed points. For a
    pattern that costs c*n^p this estimates the exponent p; a regression over the
    whole curve is far more stable against scheduler/GC/process-spawn noise on
    shared CI runners than a single adjacent-pair ratio (which used to flake)."""
    if len(pts) < 2:
        return None
    import math
    xs = [math.log(p["n"]) for p in pts]
    ys = [math.log(p["ms"]) for p in pts]
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((xs[i] - mx) * (ys[i] - my) for i in range(n))
    den = sum((xs[i] - mx) ** 2 for i in range(n))
    return None if den == 0 else num / den


def classify(points):
    # Use only points that actually completed (a budget-capped timeout would
    # understate the true growth ratio).
    usable = [p for p in points if not p["timedOut"] and p["ms"] > 1]
    any_timeout = any(p["timedOut"] for p in points)

    # Exponential schedule uses small +4 pump steps: a tiny increase in input
    # length causes a huge multiplicative jump in time (or blows the budget).
    span = (usable[-1]["n"] - usable[0]["n"]) if usable else float("inf")
    if span <= 40:
        if len(usable) >= 2 and usable[-1]["ms"] / usable[-2]["ms"] >= 3:
            return "exponential"
        if any_timeout:
            return "exponential-or-worse"
        if len(usable) < 2:
            return "unknown"
        return "polynomial"

    # Polynomial schedule (wide n range): estimate the exponent by regression.
    if len(usable) < 2:
        return "exponential-or-worse" if any_timeout else "unknown"
    p = loglog_slope(usable)
    if p is None:
        return "unknown"
    if p >= 3.6:
        return "exponential-or-worse"
    if p >= 2.6:
        return "cubic"
    if p >= 1.55:
        return "quadratic"
    return "sub-quadratic"


def verify_entry(entry):
    pattern = entry["regex"]
    flags = entry.get("flags", "")
    attack = entry["attack"]
    complexity = entry["complexity"]
    benign = entry.get("benign", "")
    sizes = attack.get("sizes") or SIZES.get(complexity) or SIZES["quadratic"]
    engine_label = "python " + ".".join(str(x) for x in sys.version_info[:3])

    # regex must compile
    try:
        re.compile(pattern, compile_flags(flags))
    except Exception as e:
        return {"id": entry["id"], "ok": False, "reason": "regex does not compile: " + str(e),
                "engineLabel": engine_label}

    # benign input must be fast
    bms, btimed, berr = measure_stable(pattern, flags, str(benign), 300)
    if berr is not None:
        return {"id": entry["id"], "ok": False, "reason": "benign compile error: " + berr, "engineLabel": engine_label}
    if btimed or bms > BENIGN_MAX_MS:
        return {"id": entry["id"], "ok": False,
                "reason": "benign input was not fast (%s)" % (">=budget" if btimed else "%.1fms" % bms),
                "engineLabel": engine_label}

    points = []
    for n in sizes:
        ms, timed_out, err = measure(pattern, flags, build_input(attack, n), BUDGET_MS)
        points.append({"n": n, "ms": None if timed_out else round(ms, 2), "timedOut": bool(timed_out)})
        if timed_out:
            break

    last = points[-1]
    last_ms = BUDGET_MS if last["timedOut"] else last["ms"]
    empirical = classify([{**p, "ms": BUDGET_MS if p["timedOut"] else p["ms"]} for p in points])
    # Blow-up is judged against the *benign* time on the SAME machine (>=20x, with
    # a tiny absolute floor above timer noise), never an absolute wall-clock bar,
    # so a merely-quadratic pattern that finishes fast on a quick CI runner is
    # still recognised. Super-linearity comes from the scale-invariant slope.
    blew_up = last["timedOut"] or last_ms >= max(BLOWUP_FLOOR_MS, 20 * max(bms, 0.05))
    superlinear = empirical in ("quadratic", "cubic", "exponential", "exponential-or-worse")
    declared_is_exp = complexity == "exponential"
    empirical_is_exp = empirical in ("exponential", "exponential-or-worse")
    class_agrees = empirical_is_exp if declared_is_exp else (
        not empirical_is_exp and empirical not in ("sub-quadratic", "unknown"))

    return {
        "id": entry["id"],
        "ok": bool(blew_up and superlinear),
        "reason": None if (blew_up and superlinear) else "did not exhibit super-linear blow-up on this engine",
        "benignMs": round(bms, 2),
        "points": points,
        "empiricalClass": empirical,
        "declaredClass": complexity,
        "classAgrees": bool(class_agrees),
        "engineLabel": engine_label,
    }


if __name__ == "__main__":
    entry = json.load(sys.stdin)
    print(json.dumps(verify_entry(entry)))
