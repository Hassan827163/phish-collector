#!/usr/bin/env python3
"""
Pilot: kya VirusTotal ka lookup (GET) bina scan ke khud update hota hai?

Design
  - Run 1: OpenPhish feed ka snapshot save (baseline). Kuch aur nahi.
  - Run 2+: feed mein jo URLs baseline ke baad naye aaye, un mein se 20 lo.
      Group S (10): t0 par pehle lookup, phir EK dafa scan (POST).
      Group L (10): sirf lookup, kabhi scan nahi.
  - Har agla run (~2 ghante): dono groups ka sirf lookup, 24 ghante tak.
  - 24h ke baad: pilot/report.md banta hai aur pilot band.

Har VT call ka asal UTC timestamp save hota hai (GitHub ke schedule late ho sakte hain).
Free API limits: 4 calls/minute, 500/din -> yahan 16 sec ka gap aur 450/din ki had.
"""

import base64
import json
import os
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

# ---------------- settings ----------------
VT_KEY = os.environ.get("VT_API_KEY", "")
DATA_DIR = Path(os.environ.get("DATA_DIR", "data")) / "pilot"
FEED_URL = "https://openphish.com/feed.txt"
N_PER_GROUP = 10
PILOT_HOURS = 24
MIN_GAP_SECONDS = 16      # 4 calls/minute se kam
DAILY_BUDGET = 450        # 500 ki had se thoda neeche
VT_BASE = "https://www.virustotal.com/api/v3"

STATE_FILE = DATA_DIR / "state.json"
OBS_FILE = DATA_DIR / "observations.jsonl"
BUDGET_FILE = DATA_DIR / "budget.json"
REPORT_FILE = DATA_DIR / "report.md"

session = requests.Session()
session.headers.update({"x-apikey": VT_KEY, "User-Agent": "academic-phishing-research-pilot"})
_last_call = 0.0


class BudgetExhausted(Exception):
    pass


# ---------------- helpers ----------------
def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_json(path, default):
    return json.loads(path.read_text()) if path.exists() else default


def save_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))


def append_obs(obj):
    OBS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OBS_FILE.open("a") as f:
        f.write(json.dumps(obj) + "\n")


def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def use_budget():
    """Roz (UTC) ki VT calls gino; had par pahunch kar ruk jao."""
    today = now().strftime("%Y-%m-%d")
    b = load_json(BUDGET_FILE, {})
    used = b.get(today, 0)
    if used >= DAILY_BUDGET:
        raise BudgetExhausted(f"Aaj ka budget khatam ({used}/{DAILY_BUDGET})")
    b = {today: used + 1}          # sirf aaj ka record rakho
    save_json(BUDGET_FILE, b)


def vt_call(method, path, **kw):
    """Response lautata hai, ya None agar 4 koshishon ke baad bhi network fail ho."""
    global _last_call
    r = None
    for attempt in range(4):
        wait = MIN_GAP_SECONDS - (time.time() - _last_call)
        if wait > 0:
            time.sleep(wait)
        use_budget()
        _last_call = time.time()
        try:
            r = session.request(method, VT_BASE + path, timeout=30, **kw)
        except requests.RequestException:  # timeout / connection error: crash nahi, dobara koshish
            r = None
            time.sleep(30 * (attempt + 1))
            continue
        if r.status_code == 429:           # quota/rate limit
            time.sleep(60 * (attempt + 1))
            continue
        return r
    return r


# ---------------- VT operations ----------------
def lookup(url):
    t = iso(now())
    r = vt_call("GET", f"/urls/{vt_url_id(url)}")
    if r is None:
        return {"checked_at": t, "state": "error", "http_status": None}
    if r.status_code == 404:
        return {"checked_at": t, "state": "unknown"}
    if r.status_code != 200:
        return {"checked_at": t, "state": "error", "http_status": r.status_code}
    a = r.json()["data"]["attributes"]
    results = a.get("last_analysis_results", {}) or {}
    flagged = sorted(e for e, v in results.items()
                     if v.get("category") in ("malicious", "suspicious"))
    return {
        "checked_at": t,
        "state": "found",
        "last_analysis_date": a.get("last_analysis_date"),
        "first_submission_date": a.get("first_submission_date"),
        "last_submission_date": a.get("last_submission_date"),
        "times_submitted": a.get("times_submitted"),
        "stats": a.get("last_analysis_stats", {}),
        "flagged_engines": flagged,
    }


def scan(url):
    t = iso(now())
    r = vt_call("POST", "/urls", data={"url": url})
    out = {"scanned_at": t, "http_status": r.status_code if r is not None else None}
    if r is not None and r.status_code == 200:
        out["analysis_id"] = r.json().get("data", {}).get("id")
    return out


def fetch_feed():
    r = requests.get(FEED_URL, timeout=60)
    r.raise_for_status()
    return {line.strip() for line in r.text.splitlines() if line.strip().startswith("http")}


# ---------------- phases ----------------
def phase_baseline(state):
    feed = fetch_feed()
    t = iso(now())
    if "baseline" not in state:
        state.update(phase="baseline", baseline=sorted(feed), baseline_at=t, candidates={})
        print(f"Baseline save: {len(feed)} URLs. Agle run mein naye URLs chune jayenge.")
        return

    known = set(state["baseline"]) | set(state["candidates"])
    for u in feed - known:
        state["candidates"][u] = t          # feed par pehli dafa kab dikha
    print(f"Naye candidates ab tak: {len(state['candidates'])}")

    need = 2 * N_PER_GROUP
    if len(state["candidates"]) < need:
        print(f"Abhi {need} naye URLs nahi. Agle run mein dobara koshish.")
        return

    # sabse taaza candidates lo, phir random groups
    newest = sorted(state["candidates"].items(), key=lambda kv: kv[1], reverse=True)[:need]
    urls = [u for u, _ in newest]
    random.shuffle(urls)
    picked = []
    for i, u in enumerate(urls):
        group = "S" if i < N_PER_GROUP else "L"
        t0 = iso(now())
        before = lookup(u)                                  # scan se pehle ki halat
        rec = {"url": u, "group": group, "feed_seen_at": state["candidates"][u], "t0": t0}
        obs = {"url": u, "group": group, "kind": "t0_lookup", "hours_since_t0": 0.0, **before}
        append_obs(obs)
        if group == "S":
            append_obs({"url": u, "group": group, "kind": "scan", **scan(u)})
        picked.append(rec)
    state.update(phase="running", urls=picked, started_at=iso(now()))
    state.pop("baseline", None)
    state.pop("candidates", None)
    print(f"Pilot shuru: {len(picked)} URLs (S={N_PER_GROUP}, L={N_PER_GROUP}).")


def phase_running(state):
    active = 0
    for rec in state["urls"]:
        hrs = (now() - parse_iso(rec["t0"])).total_seconds() / 3600
        if hrs > PILOT_HOURS + 1.5:
            continue
        active += 1
        res = lookup(rec["url"])
        append_obs({"url": rec["url"], "group": rec["group"], "kind": "poll",
                    "hours_since_t0": round(hrs, 2), **res})
    print(f"Is run mein {active} URLs check hue.")
    if active == 0:
        write_report(state)
        state["phase"] = "done"
        print("Pilot mukammal. Report: pilot/report.md")


# ---------------- report ----------------
def write_report(state):
    obs = [json.loads(l) for l in OBS_FILE.read_text().splitlines() if l.strip()]
    by_url = {}
    for o in obs:
        by_url.setdefault(o["url"], []).append(o)

    rows, summary = [], {"S": [], "L": []}
    for i, rec in enumerate(state["urls"], 1):
        o = by_url.get(rec["url"], [])
        t0 = next((x for x in o if x["kind"] == "t0_lookup"), {})
        polls = [x for x in o if x["kind"] == "poll"]
        found_polls = [x for x in polls if x.get("state") == "found"]

        def sig(x):  # report ki "pehchaan": unknown/found + last_analysis_date
            return (x.get("state"), x.get("last_analysis_date"))

        ok_polls = [x for x in polls if x.get("state") in ("found", "unknown")]
        # (a) t0 lookup -> pehli poll: S mein ye hamare scan ka asar hai, L mein organic badlaav
        changed_first = bool(t0) and bool(ok_polls) and t0.get("state") in ("found", "unknown") \
            and sig(t0) != sig(ok_polls[0])
        # (b) polls ke dauran badlaav (unknown -> found bhi gina jata hai)
        changed_polls = len({sig(x) for x in ok_polls}) > 1
        first_mal = next((x["hours_since_t0"] for x in found_polls
                          if x["stats"].get("malicious", 0) >= 1), None)
        first_mal5 = next((x["hours_since_t0"] for x in found_polls
                           if x["stats"].get("malicious", 0) >= 5), None)
        max_mal = max((x["stats"].get("malicious", 0) for x in found_polls), default=0)
        t0_state = t0.get("state", "-")
        if t0_state == "found":
            t0_state += f" ({t0['stats'].get('malicious', 0)} mal)"
        yn = lambda b: "haan" if b else "nahi"
        rows.append(f"| {i} | {rec['group']} | {t0_state} | {len(polls)} | "
                    f"{yn(changed_first)} | {yn(changed_polls)} | "
                    f"{first_mal if first_mal is not None else '-'} | "
                    f"{first_mal5 if first_mal5 is not None else '-'} | {max_mal} |")
        summary[rec["group"]].append({
            "t0_unknown": t0.get("state") == "unknown",
            "changed_first": changed_first,
            "changed_polls": changed_polls,
            "first_mal": first_mal,
            "first_mal5": first_mal5,
        })

    def med(xs):
        xs = [x for x in xs if x is not None]
        return f"{statistics.median(xs):.1f}h" if xs else "-"

    lines = [
        "# Pilot report", "",
        f"Shuru: {state.get('started_at')}  |  Har group: {N_PER_GROUP} URLs  |  Muddat: {PILOT_HOURS}h", "",
        "## Khulasa", "",
        "| Group | t0 par VT mein nahi (unknown) | t0 -> pehli poll report badli | Polls ke dauran report badli | 1+ engine (median) | 5+ engines (median) | 24h tak 5+ engines |",
        "|---|---|---|---|---|---|---|",
    ]
    for g in ("S", "L"):
        s = summary[g]
        lines.append(
            f"| {g} | {sum(x['t0_unknown'] for x in s)}/{len(s)} | "
            f"{sum(x['changed_first'] for x in s)}/{len(s)} | "
            f"{sum(x['changed_polls'] for x in s)}/{len(s)} | "
            f"{med([x['first_mal'] for x in s])} | {med([x['first_mal5'] for x in s])} | "
            f"{sum(x['first_mal5'] is not None for x in s)}/{len(s)} |")
    lines += [
        "", "**Kaise parhein:**",
        "- **L group:** agar dono \"badli\" columns zyada tar *nahi* hain, to lookup-only system ko "
        "VT ki purani/khaali report hi milti hai -> L/S design zaroori hai. Agar L ki report bhi khud "
        "badalti rahi (unknown -> found bhi), to ek hi group kaafi ho sakta hai.",
        "- **S group:** \"t0 -> pehli poll\" mein hamare apne scan ka result aana chahiye (ye sirf check hai). "
        "Asal sawaal \"polls ke dauran badli\" hai: Peng et al. (2019) ke mutabiq vendors ki baad wali "
        "detections tab tak lookup mein nahi aatin jab tak koi naya scan na ho.", "",
        "## Har URL", "",
        "| # | Group | t0 halat | Polls | t0 -> pehli poll badli? | Polls ke dauran badli? | 1+ engine (h) | 5+ engines (h) | Max malicious |",
        "|---|---|---|---|---|---|---|---|---|",
        *rows, "",
        "_Note: unknown -> found bhi \"badli\" gina jata hai. S group ka t0 lookup hamare scan se pehle ka hai._",
    ]
    REPORT_FILE.write_text("\n".join(lines))


# ---------------- main ----------------
def main():
    if not VT_KEY:
        sys.exit("VT_API_KEY secret nahi mila.")
    state = load_json(STATE_FILE, {})
    phase = state.get("phase", "baseline")
    try:
        if phase == "baseline":
            phase_baseline(state)
        elif phase == "running":
            phase_running(state)
        else:
            print("Pilot pehle hi mukammal hai. Workflow disable kar dein.")
    except BudgetExhausted as e:
        print(e)
    finally:
        save_json(STATE_FILE, state)


if __name__ == "__main__":
    main()
