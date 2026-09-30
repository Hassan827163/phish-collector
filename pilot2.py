#!/usr/bin/env python3
"""
Pilot 2: kaunsa phishing source URLs ko VirusTotal se PEHLE pakadta hai?

Har run (~15 min, cron-job.org se trigger):
  1. Har source se naye URLs dekho, aur har source se max 1 URL chuno
     (har source ke liye 2 picks mein kam az kam 45 min ka fasla, roz max 30).
       - openphish : free feed (comparison ke liye)
       - urlscan   : urlscan.io par doosron ki public scans jin ka verdict malicious hai
       - urlhaus   : URLhaus recent URLs (sirf agar URLHAUS_KEY secret mojood ho)
  2. Chune gaye URL ka VirusTotal LOOKUP (sirf GET, kabhi scan nahi) = t0 halat.
  3. Jo URLs 24h purane ho gaye, un ka dobara lookup = 24h halat.
  4. PILOT_DAYS ke baad naye picks band; aakhri 24h rechecks ke baad report.

Output (private data repo mein): pilot2/observations.jsonl, pilot2/state.json, pilot2/report.md
Har call ka asal UTC timestamp save hota hai.
"""

import base64
import hashlib
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

# ---------------- settings ----------------
VT_KEY = os.environ.get("VT_API_KEY", "")
URLSCAN_KEY = os.environ.get("URLSCAN_API_KEY", "")
URLHAUS_KEY = os.environ.get("URLHAUS_KEY", "")
DATA_DIR = Path(os.environ.get("DATA_DIR", "data")) / "pilot2"

PILOT_DAYS = 3               # itne din naye URLs chunne hain
RECHECK_HOURS = 24           # t0 ke baad dobara lookup
MIN_PICK_GAP_MIN = 45        # ek source se do picks ke darmiyan kam az kam
MAX_PER_SOURCE_PER_DAY = 30
MIN_GAP_SECONDS = 16         # VT free: 4 calls/minute
DAILY_BUDGET = 400           # VT free ~500/din; thoda margin
MAX_RUN_SECONDS = 11 * 60    # 15-min cadence mein run khatam ho jaye

VT_BASE = "https://www.virustotal.com/api/v3"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/"
# urlscan ke liye kuch queries; pehli jo results de, wahi use hoti hai (state mein note hoti hai)
# free plan: verdicts.* search nahi hota, is liye submit karne walon ke tags use karte hain
URLSCAN_QUERIES = [
    "task.tags:phishing AND date:>now-3h",
    "(task.tags:phish OR task.tags:scam OR task.tags:malicious) AND date:>now-3h",
]
PHISHUNT_API = "https://phishunt.io/api/v1/domains"
PHISHUNT_RAW = "https://raw.githubusercontent.com/0xDanielLopez/phishunt-feed/main/feed.json"

STATE_FILE = DATA_DIR / "state.json"
OBS_FILE = DATA_DIR / "observations.jsonl"
BUDGET_FILE = DATA_DIR / "vt_budget.json"
REPORT_FILE = DATA_DIR / "report.md"
LOG_FILE = DATA_DIR / "run_log.jsonl"

vt = requests.Session()
vt.headers.update({"x-apikey": VT_KEY, "User-Agent": "academic-phishing-research-pilot2"})
_last_vt_call = 0.0
_run_started = time.time()


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


def append_jsonl(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(obj) + "\n")


def h(url):
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def time_left():
    return MAX_RUN_SECONDS - (time.time() - _run_started)


# ---------------- VirusTotal (sirf lookup) ----------------
def use_budget():
    today = now().strftime("%Y-%m-%d")
    b = load_json(BUDGET_FILE, {})
    used = b.get(today, 0)
    if used >= DAILY_BUDGET:
        raise BudgetExhausted(f"Aaj ka VT budget khatam ({used}/{DAILY_BUDGET})")
    save_json(BUDGET_FILE, {today: used + 1})


def vt_lookup(url):
    """Sirf GET. Kabhi scan (POST) nahi, taake measurement par hamara asar na ho."""
    global _last_vt_call
    t = iso(now())
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    r = None
    for attempt in range(3):
        wait = MIN_GAP_SECONDS - (time.time() - _last_vt_call)
        if wait > 0:
            time.sleep(wait)
        use_budget()
        _last_vt_call = time.time()
        try:
            r = vt.get(f"{VT_BASE}/urls/{url_id}", timeout=30)
        except requests.RequestException:
            r = None
            time.sleep(20 * (attempt + 1))
            continue
        if r.status_code == 429:
            time.sleep(60)
            continue
        break
    if r is None:
        return {"checked_at": t, "state": "error", "http_status": None}
    if r.status_code == 404:
        return {"checked_at": t, "state": "unknown"}
    if r.status_code != 200:
        return {"checked_at": t, "state": "error", "http_status": r.status_code}
    a = r.json()["data"]["attributes"]
    return {
        "checked_at": t,
        "state": "found",
        "last_analysis_date": a.get("last_analysis_date"),
        "first_submission_date": a.get("first_submission_date"),
        "times_submitted": a.get("times_submitted"),
        "stats": a.get("last_analysis_stats", {}),
    }


# ---------------- sources ----------------
def src_openphish(state):
    """Feed mein naye URLs (pichle run ke snapshot ke muqable mein)."""
    r = requests.get(OPENPHISH_FEED, timeout=60)
    r.raise_for_status()
    feed = {l.strip() for l in r.text.splitlines() if l.strip().startswith("http")}
    prev = set(state.get("openphish_prev", []))
    state["openphish_prev"] = sorted(feed)
    if not prev:                      # pehla run: sirf baseline
        return []
    t = iso(now())
    return [{"url": u, "source_time": t, "meta": {}} for u in sorted(feed - prev)]


def src_urlscan(state):
    if not URLSCAN_KEY:
        return []
    headers = {"API-Key": URLSCAN_KEY}
    queries = [state["urlscan_query"]] if state.get("urlscan_query") else URLSCAN_QUERIES
    for q in queries:
        try:
            r = requests.get(URLSCAN_SEARCH, params={"q": q, "size": 100}, headers=headers, timeout=60)
        except requests.RequestException as e:
            state.setdefault("errors", []).append({"at": iso(now()), "src": "urlscan", "err": str(e)[:200]})
            continue
        if r.status_code != 200:
            state.setdefault("errors", []).append(
                {"at": iso(now()), "src": "urlscan", "query": q, "http_status": r.status_code,
                 "body": r.text[:200]})
            continue
        out = []
        for res in r.json().get("results", []):
            task = res.get("task", {}) or {}
            u = task.get("url")
            tt = task.get("time")          # urlscan scan ka waqt, maslan 2026-09-30T08:00:00.123Z
            if not u or not u.startswith("http"):
                continue
            src_time = tt[:19] + "Z" if tt else iso(now())
            out.append({"url": u, "source_time": src_time,
                        "meta": {"urlscan_id": res.get("_id"),
                                 "scan_visibility": task.get("visibility"),
                                 "scan_method": task.get("method")}})
        if out and not state.get("urlscan_query"):
            state["urlscan_query"] = q     # jo query kaam kare, usay yaad rakho
        if out:
            return out
    return []


def src_urlhaus(state):
    if not URLHAUS_KEY:
        return []
    r = requests.get(URLHAUS_RECENT, headers={"Auth-Key": URLHAUS_KEY}, timeout=60)
    if r.status_code != 200:
        state.setdefault("errors", []).append({"at": iso(now()), "src": "urlhaus", "http_status": r.status_code})
        return []
    out = []
    for x in r.json().get("urls", []) or []:
        u = x.get("url")
        da = x.get("date_added", "")       # "2026-09-30 08:00:00 UTC"
        try:
            st = iso(datetime.strptime(da[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc))
        except ValueError:
            st = iso(now())
        if u:
            out.append({"url": u, "source_time": st, "meta": {"threat": x.get("threat"), "tags": x.get("tags")}})
    return out


def _ph_records(js):
    """phishunt ka JSON list ho ya {results/data/domains: [...]}, dono sambhalo."""
    if isinstance(js, list):
        return js
    if isinstance(js, dict):
        for k in ("results", "data", "domains", "items"):
            if isinstance(js.get(k), list):
                return js[k]
    return []


def _to_iso(v):
    if not v:
        return None
    if isinstance(v, (int, float)):
        return iso(datetime.fromtimestamp(v, timezone.utc))
    s = str(v).replace("T", " ")[:19]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return iso(datetime.strptime(s[:len(fmt) + 2 if "%H" in fmt else 10], fmt).replace(tzinfo=timezone.utc))
        except ValueError:
            continue
    return None


def src_phishunt(state):
    """Certificate Transparency se mile naye suspicious phishing domains (free, bina key)."""
    js = None
    for url in (PHISHUNT_API, PHISHUNT_RAW):
        try:
            r = requests.get(url, params={"limit": 500} if url == PHISHUNT_API else None, timeout=60)
            if r.status_code == 200:
                js = r.json()
                state["phishunt_endpoint"] = url
                break
            state.setdefault("errors", []).append({"at": iso(now()), "src": "phishunt", "url": url,
                                                   "http_status": r.status_code})
        except (requests.RequestException, ValueError) as e:
            state.setdefault("errors", []).append({"at": iso(now()), "src": "phishunt", "url": url,
                                                   "err": str(e)[:200]})
    if js is None:
        return []
    out = []
    for x in _ph_records(js):
        if isinstance(x, str):
            x = {"url": x}
        if not isinstance(x, dict):
            continue
        u = x.get("url") or x.get("domain") or x.get("hostname")
        if not u:
            continue
        if not str(u).startswith("http"):
            u = "https://" + str(u).strip("/") + "/"
        st = _to_iso(x.get("first_seen")) or _to_iso(x.get("date")) or iso(now())
        meta = {k: x.get(k) for k in ("company", "score", "verdict", "malicious_openphish",
                                     "malicious_urlscan", "malicious_google") if k in x}
        out.append({"url": u, "source_time": st, "meta": meta})
    if not state.get("phishunt_sample"):
        state["phishunt_sample"] = _ph_records(js)[:2]   # pehli dafa format dekhne ke liye
    return out


SOURCES = {"openphish": src_openphish, "urlscan": src_urlscan, "urlhaus": src_urlhaus,
           "phishunt": src_phishunt}


# ---------------- phases ----------------
def can_pick(state, src):
    today = now().strftime("%Y-%m-%d")
    per_day = state.setdefault("picks_per_day", {}).setdefault(src, {})
    if per_day.get(today, 0) >= MAX_PER_SOURCE_PER_DAY:
        return False
    last = state.setdefault("last_pick", {}).get(src)
    if last and now() - parse_iso(last) < timedelta(minutes=MIN_PICK_GAP_MIN):
        return False
    return True


def pick_new(state):
    started = parse_iso(state["started_at"])
    if now() - started > timedelta(days=PILOT_DAYS):
        return
    seen = set(state.setdefault("seen", []))
    for src, fn in SOURCES.items():
        try:
            cands = fn(state)
        except Exception as e:     # ek source ki kharabi baqi ko na roke
            state.setdefault("errors", []).append({"at": iso(now()), "src": src, "err": str(e)[:200]})
            continue
        # queue: jo candidates abhi nahi chune gaye, agle runs ke liye yaad rakho
        queue = state.setdefault("queue", {}).setdefault(src, [])
        queued = {x["url"] for x in queue}
        fresh_c = [c for c in cands if h(c["url"]) not in seen and c["url"] not in queued]
        state.setdefault("candidates_seen", {})
        state["candidates_seen"][src] = state["candidates_seen"].get(src, 0) + len(fresh_c)
        queue.extend(fresh_c)
        # sirf pichle 12h ke candidates rakho, max 300
        cutoff = iso(now() - timedelta(hours=12))
        queue[:] = sorted([x for x in queue if x["source_time"] >= cutoff and h(x["url"]) not in seen],
                          key=lambda x: x["source_time"], reverse=True)[:300]
        if not queue or not can_pick(state, src) or time_left() < 60:
            continue
        c = queue.pop(0)                                   # sabse taaza
        res = vt_lookup(c["url"])
        rec = {"url": c["url"], "source": src, "source_time": c["source_time"],
               "t0": res["checked_at"], "meta": c["meta"], "rechecked": False}
        state.setdefault("urls", []).append(rec)
        seen.add(h(c["url"]))
        append_jsonl(OBS_FILE, {"url": c["url"], "source": src, "kind": "t0", "hours_since_t0": 0.0, **res})
        today = now().strftime("%Y-%m-%d")
        state["picks_per_day"][src][today] = state["picks_per_day"][src].get(today, 0) + 1
        state["last_pick"][src] = res["checked_at"]
    state["seen"] = sorted(seen)


def recheck_due(state):
    for rec in state.get("urls", []):
        if rec["rechecked"] or time_left() < 60:
            continue
        hrs = (now() - parse_iso(rec["t0"])).total_seconds() / 3600
        if hrs < RECHECK_HOURS:
            continue
        res = vt_lookup(rec["url"])
        append_jsonl(OBS_FILE, {"url": rec["url"], "source": rec["source"], "kind": "recheck",
                                "hours_since_t0": round(hrs, 2), **res})
        rec["rechecked"] = True


# ---------------- report ----------------
def mal(o):
    return (o.get("stats") or {}).get("malicious", 0) if o.get("state") == "found" else 0


def write_report(state):
    obs = [json.loads(l) for l in OBS_FILE.read_text().splitlines() if l.strip()] if OBS_FILE.exists() else []
    t0 = {o["url"]: o for o in obs if o["kind"] == "t0"}
    rc = {o["url"]: o for o in obs if o["kind"] == "recheck"}
    lines = ["# Pilot 2 report: kaunsa source VirusTotal se pehle hai?", "",
             f"Shuru: {state.get('started_at')} | urlscan query: `{state.get('urlscan_query', '-')}`", "",
             "| Source | URLs | t0 par VT mein nahi | t0 par 0 engines | t0 par 5 se kam | "
             "t0 malicious (median) | 24h par 5+ (jin ka recheck hua) | \"Fresh\" URLs* |",
             "|---|---|---|---|---|---|---|---|"]
    for src in SOURCES:
        recs = [r for r in state.get("urls", []) if r["source"] == src]
        n = len(recs)
        if n == 0:
            lines.append(f"| {src} | 0 | - | - | - | - | - | - |")
            continue
        o0 = [t0[r["url"]] for r in recs if r["url"] in t0]
        unknown = sum(o["state"] == "unknown" for o in o0)
        zero = sum(mal(o) == 0 for o in o0 if o["state"] in ("found", "unknown"))
        lt5 = sum(mal(o) < 5 for o in o0 if o["state"] in ("found", "unknown"))
        med = statistics.median([mal(o) for o in o0]) if o0 else "-"
        rch = [r for r in recs if r["url"] in rc]
        det24 = sum(mal(rc[r["url"]]) >= 5 for r in rch)
        fresh = sum(1 for r in rch if r["url"] in t0 and mal(t0[r["url"]]) < 5 and mal(rc[r["url"]]) >= 5)
        lines.append(f"| {src} | {n} | {unknown}/{n} | {zero}/{n} | {lt5}/{n} | {med} | "
                     f"{det24}/{len(rch)} | {fresh}/{len(rch)} |")
    lines += ["", "*Fresh = t0 par VT mein 5 se kam engines, lekin 24h par 5+. Yahi URLs RQ2 ke liye kaam ke hain: "
              "TI ko shuru mein pata nahi tha, baad mein chala.", "",
              "**Kaise parhein:** jis source ka \"Fresh\" aur \"t0 par 5 se kam\" hissa sabse zyada ho, "
              "asal collector usi par banega. Note: 24h par 5+ na hona ka matlab ye nahi ke URL benign hai; "
              "labels manual check se banenge.", ""]
    if state.get("candidates_seen"):
        lines += ["Naye candidates jo har source ne dikhaye (sab runs mila kar): " +
                  ", ".join(f"{k}: {v}" for k, v in state["candidates_seen"].items()), ""]
    if state.get("errors"):
        lines += [f"Errors: {len(state['errors'])} (state.json mein detail)", ""]
    REPORT_FILE.write_text("\n".join(lines))


# ---------------- main ----------------
def main():
    if not VT_KEY:
        sys.exit("VT_API_KEY secret nahi mila.")
    DATA_DIR.mkdir(parents=True, exist_ok=True)   # pehle run par folder bana do
    state = load_json(STATE_FILE, {})
    state.setdefault("started_at", iso(now()))
    state["errors"] = state.get("errors", [])[-50:]       # sirf aakhri 50 errors rakho
    phase = "picking" if now() - parse_iso(state["started_at"]) <= timedelta(days=PILOT_DAYS) else "recheck-only"
    try:
        recheck_due(state)          # pehle purane URLs ke 24h checks
        pick_new(state)
    except BudgetExhausted as e:
        print(e)
    finally:
        pending = [r for r in state.get("urls", []) if not r["rechecked"]]
        if phase == "recheck-only" and not pending:
            state["phase"] = "done"
        write_report(state)         # har run par report taaza (adhoori bhi dekh sakte hain)
        save_json(STATE_FILE, state)
        append_jsonl(LOG_FILE, {"run_at": iso(now()), "phase": state.get("phase", phase),
                                "urls_total": len(state.get("urls", [])), "pending_recheck": len(pending)})
        print(f"Phase: {state.get('phase', phase)} | URLs: {len(state.get('urls', []))} | "
              f"24h recheck baqi: {len(pending)}")


if __name__ == "__main__":
    main()