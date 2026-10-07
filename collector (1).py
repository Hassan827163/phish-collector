#!/usr/bin/env python3
"""
Main collector: "Evaluated Too Late" study (8 hafte).

Har run (~15 min, cron-job.org -> workflow_dispatch):
  1. Jo snapshots due hain, un ka VirusTotal LOOKUP (kabhi scan nahi) + liveness.
  2. Naye URLs chunna, teen groups mein:
       phishunt  (gap group)     : CT-log se naye domains, first_seen < 120 min (v1: 60), verdict != noise
       openphish (control group) : OpenPhish free feed (feed-time t0)
       benign    (candidates)    : B1 = Tranco top-1M ke naye entries, B2 = phishunt "noise" (taaza)
  3. t0 par DNS / ASN / RDAP (domain age) / grouping keys save; ye baad mein nahi badalte.
  4. OpenPhish feed mein hamare active hosts dikhen to "feed_seen" record (label mein sirf madad).

Snapshots (ghante, t0 se):
  phishunt, openphish : URL @ 0,1,2,4,24,72,168 + domain @ 0,72,168 = 10 VT calls
  benign              : URL @ 0,72          +  domain @ 0,72      = 4 VT calls

VT free: 4 calls/min, 500/din (UTC). Yahan 16 sec gap aur 485/din hard cap.
Roz ke caps: phishunt 30, openphish 10, benign 15 (B1 10 + B2 5) <= 460 calls/din.
(Asal mein phishunt ~20/din milte hain; v2 (8 Oct 2026): 2h + 7d snapshots, zyada benign,
 phishunt window 60 -> 120 min (sab se taaza pehle), har URL par collector_version, supply diagnostics.)

Output (DATA_DIR/main/):
  urls.jsonl    : har chune gaye URL ka ek record (static, t0 par)
  obs.jsonl     : har snapshot/observation ki ek line
  state.json    : queues, counters, active URLs ka schedule
  run_log.jsonl : har run ka khulasa
  report.md     : har run par taaza khulasa
"""

import base64
import gzip
import hashlib
import io
import json
import os
import random
import re
import socket
import statistics
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

try:
    import dns.resolver
    import dns.reversename
except ImportError:          # tests / local runs bina dnspython ke
    dns = None

try:
    import tldextract
    _TLD_PRIV = tldextract.TLDExtract(include_psl_private_domains=True)
    _TLD_PUB = tldextract.TLDExtract(include_psl_private_domains=False)
except ImportError:
    tldextract = None

# ======================= settings =======================
VT_KEY = os.environ.get("VT_API_KEY", "")
DATA_DIR = Path(os.environ.get("DATA_DIR", "data")) / "main"

STUDY_DAYS = int(os.environ.get("STUDY_DAYS", "56"))     # 8 hafte naye picks; phir sirf snapshots
MIN_GAP_SECONDS = 16          # VT free: 4 calls/min
DAILY_VT_CAP = 485            # VT free: 500/din (UTC); thoda margin
MAX_RUN_SECONDS = 12 * 60 + 30
HTTP_TIMEOUT = 10

DAILY_CAP = {"phishunt": 30, "openphish": 10, "benign_tranco": 10, "benign_phishunt": 5}
BURST = {"phishunt": 4, "openphish": 2, "benign_tranco": 1, "benign_phishunt": 1}  # pacing ke upar chhoot
MAX_PICKS_PER_RUN = {"phishunt": 6, "openphish": 2, "benign_tranco": 1, "benign_phishunt": 1}

COLLECTOR_VERSION = 2
PHISHUNT_MAX_AGE_MIN = 120    # gap group: first_seen se itne minute tak (v1: 60). pick_delay_min se analysis mein alag ho sakta hai
BENIGN_PH_MAX_AGE_MIN = 360   # B2 (noise) ke liye thodi dheel
OPENPHISH_QUEUE_HOURS = 12

SCHEDULES = {
    # snapshot naam -> (ghante, [VT calls])
    "full": {"t0": (0, ["url", "domain"]), "1h": (1, ["url"]), "2h": (2, ["url"]), "4h": (4, ["url"]),
             "24h": (24, ["url"]), "72h": (72, ["url", "domain"]), "7d": (168, ["url", "domain"])},
    "light": {"t0": (0, ["url", "domain"]), "72h": (72, ["url", "domain"])},
}
GROUP_SCHEDULE = {"phishunt": "full", "openphish": "full", "benign": "light"}
# v1 (6-7 Oct) ke URLs ka 2h snapshot nahi tha; unhein ab late 2h nahi dena. 7d unhein bhi milega.
V1_FULL_PLAN = ["t0", "1h", "4h", "24h", "72h", "7d"]


def plan_of(rec):
    """Is URL ke liye kaun se snapshots hain (purane records ke liye v1 plan)."""
    sched = SCHEDULES[GROUP_SCHEDULE[rec["group"]]]
    if "plan" in rec:
        return [n for n in rec["plan"] if n in sched]
    if GROUP_SCHEDULE[rec["group"]] == "full":
        return V1_FULL_PLAN
    return list(sched)

VT_BASE = "https://www.virustotal.com/api/v3"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
PHISHUNT_API = "https://phishunt.io/api/v1/domains"
PHISHUNT_RAW = "https://raw.githubusercontent.com/0xDanielLopez/phishunt-feed/main/feed.json"
RDAP = "https://rdap.org/domain/"
UA = "academic-phishing-research (non-commercial study)"

URLS_FILE = DATA_DIR / "urls.jsonl"
OBS_FILE = DATA_DIR / "obs.jsonl"
STATE_FILE = DATA_DIR / "state.json"
LOG_FILE = DATA_DIR / "run_log.jsonl"
REPORT_FILE = DATA_DIR / "report.md"

vt = requests.Session()
vt.headers.update({"x-apikey": VT_KEY, "User-Agent": UA})
web = requests.Session()
web.headers.update({"User-Agent": UA})
_last_vt_call = 0.0
_run_started = time.time()


class BudgetExhausted(Exception):
    pass


# ======================= helpers =======================
def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def to_iso(v):
    """phishunt/RDAP ke mukhtalif time formats -> ISO UTC."""
    if not v:
        return None
    if isinstance(v, (int, float)):
        return iso(datetime.fromtimestamp(v, timezone.utc))
    s = str(v).strip().replace("T", " ").replace("Z", "")
    s = re.sub(r"\.\d+", "", s)            # fractional seconds
    s = re.sub(r"[+-]\d\d:?\d\d$", "", s)  # timezone (UTC maan kar)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return iso(datetime.strptime(s, fmt).replace(tzinfo=timezone.utc))
        except ValueError:
            continue
    return None


def load_json(path, default):
    return json.loads(path.read_text()) if path.exists() else default


def save_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=1))
    tmp.replace(path)


def append_jsonl(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def uid(url):
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def audit_rank(url):
    """Fixed random number (URL se). Manual sample = har group ke sab se chhote ranks."""
    return int(hashlib.sha256(("audit:" + url).encode()).hexdigest()[:12], 16) / 16 ** 12


def time_left():
    return MAX_RUN_SECONDS - (time.time() - _run_started)


def host_of(url):
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#:]+)", url)
    return (m.group(1) if m else "").lower().rstrip(".")


def today_key():
    return now().strftime("%Y-%m-%d")


def log_error(state, src, err):
    state.setdefault("errors", []).append({"at": iso(now()), "src": src, "err": str(err)[:300]})
    state["errors"] = state["errors"][-100:]


# ======================= grouping keys =======================
_KEEP_TOKENS = {
    "login", "signin", "secure", "verify", "account", "accounts", "update", "support", "help",
    "auth", "sso", "bank", "wallet", "pay", "app", "www", "mail", "web", "online", "service",
    "biz", "com", "net", "org", "id", "my", "portal", "billing", "confirm", "security",
}


def _token_shape(tok):
    """Ek label-token ki 'shakal': keyword ho to wahi, warna a/0 ki shape."""
    t = tok.lower()
    if t in _KEEP_TOKENS:
        return t
    t = re.sub(r"[a-z]+", "a", t)
    t = re.sub(r"[0-9]+", "0", t)
    return t


def grouping_keys(host):
    out = {"etld1": host, "registered_domain": host, "shared_platform": False, "pattern_key": host}
    if tldextract is not None:
        try:
            p = _TLD_PRIV(host)
            q = _TLD_PUB(host)
            etld1 = ".".join(x for x in (p.domain, p.suffix) if x) or host
            reg = ".".join(x for x in (q.domain, q.suffix) if x) or host
            out.update(etld1=etld1, registered_domain=reg, shared_platform=(etld1 != reg),
                       suffix=p.suffix, subdomain=p.subdomain)
            label = p.domain
            sub = p.subdomain
        except Exception:
            label, sub = host.split(".")[0], ""
            out["suffix"] = ".".join(host.split(".")[1:])
    else:
        parts = host.split(".")
        label, sub = (parts[-2] if len(parts) > 1 else parts[0]), ".".join(parts[:-2])
        out["suffix"] = parts[-1] if len(parts) > 1 else ""
    shape = "-".join(_token_shape(t) for t in re.split(r"[-_]", label) if t)
    sub_shape = ".".join("-".join(_token_shape(t) for t in re.split(r"[-_]", s) if t)
                         for s in sub.split(".") if s) if sub else ""
    out["pattern_key"] = ".".join(x for x in (sub_shape, shape, out.get("suffix", "")) if x)
    return out


# ======================= t0 enrichment (no VT) =======================
def dns_info(host):
    res = {"host": host}
    if dns is None:
        try:
            res["a"] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
            res["resolved"] = bool(res["a"])
        except Exception as e:
            res.update(resolved=False, error=type(e).__name__)
        return res
    r = dns.resolver.Resolver()
    r.lifetime = 6
    try:
        ans = r.resolve(host, "A")
        res["a"] = sorted(a.to_text() for a in ans)
        res["a_ttl"] = ans.rrset.ttl
        res["resolved"] = True
    except Exception as e:
        res.update(resolved=False, error=type(e).__name__)
    for rtype in ("AAAA", "NS", "MX"):
        try:
            res[rtype.lower()] = sorted(x.to_text() for x in r.resolve(host, rtype))
        except Exception:
            pass
    if res.get("a"):
        try:                                   # Team Cymru: IP -> ASN, prefix, mulk (free, DNS)
            ip = res["a"][0]
            q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
            txt = r.resolve(q, "TXT")[0].to_text().strip('"')
            asn, prefix, cc, *_ = [x.strip() for x in txt.split("|")]
            res.update(asn=asn.split()[0], prefix=prefix, country=cc)
        except Exception:
            pass
    return res


def rdap_info(domain):
    """Domain registration date (RDAP). Shared platforms (pages.dev waghera) ke liye bematlab."""
    try:
        r = web.get(RDAP + domain, timeout=HTTP_TIMEOUT, headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return {"ok": False, "http_status": r.status_code}
        js = r.json()
        ev = {e.get("eventAction"): e.get("eventDate") for e in js.get("events", []) if isinstance(e, dict)}
        reg = to_iso(ev.get("registration"))
        out = {"ok": True, "registered": reg, "last_changed": to_iso(ev.get("last changed")),
               "expires": to_iso(ev.get("expiration"))}
        for ent in js.get("entities", []) or []:
            if "registrar" in (ent.get("roles") or []):
                try:
                    out["registrar"] = ent["vcardArray"][1][1][3]
                except Exception:
                    pass
        return out
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}


def liveness(url):
    """Sirf HTTP status. Redirect follow nahi, body kabhi download nahi."""
    t = iso(now())
    try:
        r = web.head(url, allow_redirects=False, timeout=HTTP_TIMEOUT)
        if r.status_code in (403, 405, 501):
            r = web.get(url, allow_redirects=False, timeout=HTTP_TIMEOUT, stream=True)
            r.close()
        loc = r.headers.get("Location")
        return {"checked_at": t, "live": True, "http_status": r.status_code,
                "redirect_host": host_of(loc) if loc and "://" in loc else (loc[:80] if loc else None)}
    except requests.RequestException as e:
        return {"checked_at": t, "live": False, "error": type(e).__name__}


# ======================= VirusTotal (sirf GET) =======================
def use_vt_budget(state):
    b = state.setdefault("vt_calls", {})
    d = today_key()
    if b.get(d, 0) >= DAILY_VT_CAP:
        raise BudgetExhausted(f"Aaj ka VT budget khatam ({b.get(d)}/{DAILY_VT_CAP})")
    b[d] = b.get(d, 0) + 1
    for k in list(b):                         # sirf pichle 10 din rakho
        if k < iso(now() - timedelta(days=10))[:10]:
            del b[k]


def vt_calls_today(state):
    return state.get("vt_calls", {}).get(today_key(), 0)


def vt_get(state, path):
    global _last_vt_call
    r = None
    for attempt in range(3):
        wait = MIN_GAP_SECONDS - (time.time() - _last_vt_call)
        if wait > 0:
            time.sleep(wait)
        use_vt_budget(state)
        _last_vt_call = time.time()
        try:
            r = vt.get(VT_BASE + path, timeout=30)
        except requests.RequestException:
            r = None
            time.sleep(15 * (attempt + 1))
            continue
        if r.status_code == 429:
            log_error(state, "vt", "429 rate/quota")
            time.sleep(60)
            continue
        break
    return r


def _vt_parse(r, kind):
    if r is None:
        return {"state": "error", "http_status": None}
    if r.status_code == 404:
        return {"state": "unknown"}
    if r.status_code != 200:
        return {"state": "error", "http_status": r.status_code}
    a = (r.json().get("data") or {}).get("attributes") or {}
    res = a.get("last_analysis_results") or {}
    out = {
        "state": "found",
        "stats": a.get("last_analysis_stats", {}),
        "last_analysis_date": a.get("last_analysis_date"),
        "flagged_engines": sorted(e for e, v in res.items()
                                  if (v or {}).get("category") in ("malicious", "suspicious")),
        "reputation": a.get("reputation"),
    }
    if kind == "url":
        out.update(first_submission_date=a.get("first_submission_date"),
                   last_submission_date=a.get("last_submission_date"),
                   times_submitted=a.get("times_submitted"))
    else:
        out.update(creation_date=a.get("creation_date"), categories=a.get("categories"))
    return out


def vt_url(state, url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return _vt_parse(vt_get(state, f"/urls/{url_id}"), "url")


def vt_domain(state, domain):
    return _vt_parse(vt_get(state, f"/domains/{domain}"), "domain")


# ======================= sources =======================
def fetch_phishunt(state):
    try:
        r = web.get(PHISHUNT_API, params={"limit": 500}, timeout=60)
        r.raise_for_status()
        js = r.json()
    except Exception as e:
        log_error(state, "phishunt_api", e)
        r = web.get(PHISHUNT_RAW, timeout=60)     # backup (pilot 2 wala)
        r.raise_for_status()
        js = r.json()
    recs = js if isinstance(js, list) else next(
        (js[k] for k in ("results", "data", "domains", "items") if isinstance(js.get(k), list)), [])
    out = []
    for x in recs:
        if not isinstance(x, dict):
            continue
        u = x.get("url") or x.get("domain")
        if not u:
            continue
        u = str(u).strip()
        if not u.startswith("http"):
            u = "https://" + u.strip("/") + "/"
        fs = to_iso(x.get("first_seen")) or to_iso(x.get("date"))
        if not fs:
            continue
        meta = {k: x.get(k) for k in ("company", "score", "verdict", "malicious_google", "malicious_openphish",
                                      "malicious_phishtank", "malicious_tweetfeed", "malicious_urlscan",
                                      "cert", "ip", "asn", "org", "country", "uuid") if k in x}
        out.append({"url": u, "source_time": fs, "meta": meta})
    return out


def fetch_openphish():
    r = web.get(OPENPHISH_FEED, timeout=60)
    r.raise_for_status()
    return {l.strip() for l in r.text.splitlines() if l.strip().startswith("http")}


def tranco_new_entries(state):
    """Din mein ek dafa: aaj ki Tranco list mein jo domains kal nahi thay (top 1M)."""
    d = (now() - timedelta(days=1)).strftime("%Y-%m-%d")
    if state.get("tranco_day") == d:
        return
    last_try = state.get("tranco_last_try")
    if last_try and now() - parse_iso(last_try) < timedelta(hours=3):
        return                                 # fail hone par har run mein bhari download na ho
    state["tranco_last_try"] = iso(now())
    from tranco import Tranco              # sirf yahan chahiye
    t = Tranco(cache=True, cache_dir="/tmp/tranco_cache")
    prev_d = (now() - timedelta(days=2)).strftime("%Y-%m-%d")
    cur = set(t.list(date=d).top(1000000))
    prev = set(t.list(date=prev_d).top(1000000))
    new = sorted(cur - prev)
    random.Random(d).shuffle(new)
    state["tranco_day"] = d
    state.setdefault("queue", {})["benign_tranco"] = [
        {"url": f"https://{x}/", "source_time": iso(now()), "meta": {"tranco_date": d}} for x in new[:300]]
    state["tranco_new_count"] = len(new)


# ======================= picking =======================
def can_pick(state, src):
    d = today_key()
    n = state.setdefault("picks", {}).setdefault(src, {}).get(d, 0)
    if n >= DAILY_CAP[src]:
        return False
    frac = (now() - now().replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds() / 86400
    return n < DAILY_CAP[src] * frac + BURST[src]          # din bhar barabar phailao


def calls_for(group):
    return sum(len(v[1]) for v in SCHEDULES[GROUP_SCHEDULE[group]].values())


def calls_due_today_pending(state):
    """Aaj (UTC) ke baqi snapshots ki VT calls (purane URLs)."""
    end = now().replace(hour=23, minute=59, second=59)
    n = 0
    for rec in state.get("active", {}).values():
        for name, (h, kinds) in SCHEDULES[GROUP_SCHEDULE[rec["group"]]].items():
            if name in rec["done"] or name not in plan_of(rec):
                continue
            if parse_iso(rec["t0"]) + timedelta(hours=h) <= end:
                n += len(kinds)
    return n


def budget_allows_new(state, group):
    same_day = sum(len(k) for n, (h, k) in SCHEDULES[GROUP_SCHEDULE[group]].items() if h <= 4)
    return DAILY_VT_CAP - vt_calls_today(state) - calls_due_today_pending(state) >= same_day + 2


def register(state, cand, source, group):
    """Naya URL: grouping keys, DNS, RDAP, phir t0 snapshot (VT + liveness)."""
    url = cand["url"]
    host = host_of(url)
    keys = grouping_keys(host)
    t_pick = iso(now())
    rec = {
        "id": uid(url), "url": url, "host": host, "group": group, "source": source,
        "source_time": cand["source_time"], "picked_at": t_pick,
        "pick_delay_min": round((now() - parse_iso(cand["source_time"])).total_seconds() / 60, 1),
        "audit_rank": round(audit_rank(url), 8), "meta": cand.get("meta", {}), **keys,
        "collector_version": COLLECTOR_VERSION, "plan": list(SCHEDULES[GROUP_SCHEDULE[group]]),
    }
    rec["dns_t0"] = dns_info(host)
    rec["rdap_t0"] = rdap_info(keys["registered_domain"]) if not keys["shared_platform"] else {"ok": False, "skipped": "shared_platform"}
    rec["vt_domain_queried"] = keys["etld1"]
    state.setdefault("active", {})[rec["id"]] = {
        "url": url, "group": group, "t0": t_pick, "domain": keys["etld1"], "done": [],
        "plan": list(SCHEDULES[GROUP_SCHEDULE[group]])}
    state.setdefault("seen", {})[rec["id"]] = t_pick
    append_jsonl(URLS_FILE, rec)
    d = today_key()
    state["picks"].setdefault(source, {})[d] = state["picks"][source].get(d, 0) + 1
    state["counts"] = state.get("counts", {})
    state["counts"][source] = state["counts"].get(source, 0) + 1
    run_snapshot(state, rec["id"], "t0")


def pick_phishunt(state, records, summary=None):
    fresh, noise = [], []
    diag = {"lt60": 0, "60_120": 0, "older": 0, "noise": 0, "already_seen": 0}
    for c in records:
        if uid(c["url"]) in state.get("seen", {}):
            diag["already_seen"] += 1
            continue
        age = (now() - parse_iso(c["source_time"])).total_seconds() / 60
        if c["meta"].get("verdict") == "noise":
            diag["noise"] += 1
        else:
            diag["lt60" if age < 60 else "60_120" if age <= 120 else "older"] += 1
        if c["meta"].get("verdict") == "noise":
            # B2 = benign *candidates*. TI flags ya brand se filter NAHI karte: warna benign group
            # TI ke false positives se khaali ho jata (circular), aur phishunt har record par brand
            # (company) lagata hai, to B2 bilkul khaali reh jata. Flags meta mein save hain;
            # aakhri label manual sample (audit_rank) se banega.
            if age <= BENIGN_PH_MAX_AGE_MIN:
                noise.append(c)
        elif 0 <= age <= PHISHUNT_MAX_AGE_MIN:
            fresh.append(c)
    fresh.sort(key=lambda c: c["source_time"], reverse=True)          # sab se taaza pehle
    if summary is not None:
        summary["phishunt_supply"] = diag      # naye (pehle na chune) records ki ginti, umar ke hisaab se
    n = 0
    for c in fresh:
        if n >= MAX_PICKS_PER_RUN["phishunt"] or not can_pick(state, "phishunt") \
                or not budget_allows_new(state, "phishunt") or time_left() < 120:
            break
        register(state, c, "phishunt", "phishunt")
        n += 1
    random.shuffle(noise)
    for c in noise[:MAX_PICKS_PER_RUN["benign_phishunt"]]:
        if can_pick(state, "benign_phishunt") and budget_allows_new(state, "benign") and time_left() > 120:
            register(state, c, "benign_phishunt", "benign")


def pick_queue(state, src, group):
    q = state.setdefault("queue", {}).setdefault(src, [])
    q[:] = [c for c in q if uid(c["url"]) not in state.get("seen", {})]
    n = 0
    while q and n < MAX_PICKS_PER_RUN[src] and can_pick(state, src) \
            and budget_allows_new(state, group) and time_left() > 120:
        register(state, q.pop(0), src, group)
        n += 1


def update_openphish(state, feed):
    t = iso(now())
    prev = set(state.get("openphish_prev", []))
    state["openphish_prev"] = sorted(feed)
    if not prev:
        return                                   # pehla run: sirf baseline
    q = state.setdefault("queue", {}).setdefault("openphish", [])
    known = {c["url"] for c in q}
    new = [u for u in sorted(feed - prev) if u not in known and uid(u) not in state.get("seen", {})]
    random.shuffle(new)
    q.extend({"url": u, "source_time": t, "meta": {}} for u in new)
    cutoff = iso(now() - timedelta(hours=OPENPHISH_QUEUE_HOURS))
    q[:] = [c for c in q if c["source_time"] >= cutoff][:500]
    # label-madad: hamare active (phishunt/benign) hosts feed mein aaye?
    feed_hosts = {host_of(u) for u in feed}
    for i, rec in state.get("active", {}).items():
        if rec["group"] != "openphish" and not rec.get("feed_seen") and host_of(rec["url"]) in feed_hosts:
            rec["feed_seen"] = t
            append_jsonl(OBS_FILE, {"id": i, "kind": "feed_seen", "feed": "openphish", "checked_at": t,
                                    "hours_since_t0": round((now() - parse_iso(rec["t0"])).total_seconds() / 3600, 2)})


# ======================= snapshots =======================
def run_snapshot(state, rid, name):
    rec = state["active"][rid]
    h, kinds = SCHEDULES[GROUP_SCHEDULE[rec["group"]]][name]
    due = parse_iso(rec["t0"]) + timedelta(hours=h)
    for kind in kinds:
        res = vt_url(state, rec["url"]) if kind == "url" else vt_domain(state, rec["domain"])
        append_jsonl(OBS_FILE, {"id": rid, "kind": "vt_" + kind, "snapshot": name, "due": iso(due),
                                "checked_at": iso(now()), "hours_since_t0": round(
                                    (now() - parse_iso(rec["t0"])).total_seconds() / 3600, 3), **res})
    append_jsonl(OBS_FILE, {"id": rid, "kind": "live", "snapshot": name, **liveness(rec["url"])})
    rec["done"].append(name)
    save_json(STATE_FILE, state)       # crash/timeout par bhi urls/obs aur state mel khaate rahein


def due_snapshots(state, max_hours=None, min_hours=None):
    out = []
    for rid, rec in state.get("active", {}).items():
        for name, (h, _) in SCHEDULES[GROUP_SCHEDULE[rec["group"]]].items():
            if name in rec["done"] or name not in plan_of(rec):          # t0 bhi (agar budget ki wajah se adhoora reh gaya)
                continue
            if max_hours is not None and h > max_hours:
                continue
            if min_hours is not None and h < min_hours:
                continue
            due = parse_iso(rec["t0"]) + timedelta(hours=h)
            if due <= now():
                out.append((due, rid, name))
    return sorted(out)


def process_due(state, **kw):
    for _, rid, name in due_snapshots(state, **kw):
        if time_left() < 60:
            return
        run_snapshot(state, rid, name)


def retire_finished(state):
    for rid in list(state.get("active", {})):
        rec = state["active"][rid]
        if set(plan_of(rec)) <= set(rec["done"]):
            del state["active"][rid]


# ======================= report =======================
def write_report(state):
    urls = [json.loads(l) for l in URLS_FILE.read_text().splitlines() if l.strip()] if URLS_FILE.exists() else []
    obs = [json.loads(l) for l in OBS_FILE.read_text().splitlines() if l.strip()] if OBS_FILE.exists() else []
    vt = {}
    for o in obs:
        if o["kind"] in ("vt_url", "vt_domain"):
            vt[(o["id"], o["kind"], o["snapshot"])] = o

    def mal(o):
        return (o.get("stats") or {}).get("malicious", 0) if o and o.get("state") == "found" else None

    lines = ["# Main collector report", "",
             f"Shuru: {state.get('started_at')} | Aakhri run: {iso(now())} | Active URLs: {len(state.get('active', {}))} | "
             f"Aaj VT calls: {vt_calls_today(state)}/{DAILY_VT_CAP}", "",
             "## URL lookup: VT ne kitne URLs pakde (malicious >= 1), har snapshot par", "",
             "| Source | URLs | t0 unknown | t0 | 1h | 2h | 4h | 24h | 72h | 7d | pick delay median (min) |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for src in ("phishunt", "openphish", "benign_tranco", "benign_phishunt"):
        rs = [u for u in urls if u["source"] == src]
        if not rs:
            lines.append(f"| {src} | 0 | | | | | | | | | |")
            continue
        cells = []
        unk = sum(1 for u in rs if (vt.get((u["id"], "vt_url", "t0")) or {}).get("state") == "unknown")
        for snap in ("t0", "1h", "2h", "4h", "24h", "72h", "7d"):
            have = [vt.get((u["id"], "vt_url", snap)) for u in rs]
            have = [o for o in have if o and o.get("state") in ("found", "unknown")]
            if not have:
                cells.append("-")
                continue
            det = sum(1 for o in have if (mal(o) or 0) >= 1)
            cells.append(f"{det}/{len(have)}")
        delay = statistics.median([u["pick_delay_min"] for u in rs])
        lines.append(f"| {src} | {len(rs)} | {unk}/{len(rs)} | " + " | ".join(cells) + f" | {delay:.0f} |")
    lines += ["", "## Domain report: malicious >= 1 (t0 / 72h / 7d)", "",
              "| Source | t0 | 72h | 7d |", "|---|---|---|---|"]
    for src in ("phishunt", "openphish", "benign_tranco", "benign_phishunt"):
        rs = [u for u in urls if u["source"] == src]
        c = []
        for snap in ("t0", "72h", "7d"):
            have = [vt.get((u["id"], "vt_domain", snap)) for u in rs]
            have = [o for o in have if o and o.get("state") in ("found", "unknown")]
            c.append(f"{sum(1 for o in have if (mal(o) or 0) >= 1)}/{len(have)}" if have else "-")
        lines.append(f"| {src} | {c[0]} | {c[1]} | {c[2]} |")
    fs = sum(1 for o in obs if o["kind"] == "feed_seen")
    groups = len({u["etld1"] for u in urls})
    patterns = len({u["pattern_key"] for u in urls})
    lines += ["", f"Feed mein baad mein dikhe (phishunt/benign hosts, OpenPhish): {fs}",
              f"Distinct eTLD+1: {groups} | distinct pattern_key: {patterns} | total URLs: {len(urls)}",
              f"Tranco naye entries (aakhri din): {state.get('tranco_new_count', '-')}",
              f"Errors (aakhri 100 mein): {len(state.get('errors', []))}", "",
              "_Note: 'unknown' = VT ke paas URL ka record hi nahi. Labels VT se nahi, manual sample (audit_rank) se banenge._"]
    REPORT_FILE.write_text("\n".join(lines))


# ======================= main =======================
def main():
    if not VT_KEY:
        sys.exit("VT_API_KEY secret nahi mila.")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    state = load_json(STATE_FILE, {})
    state.setdefault("started_at", iso(now()))
    picking = now() - parse_iso(state["started_at"]) <= timedelta(days=STUDY_DAYS)
    summary = {"run_at": iso(now())}
    try:
        # 1. waqt-nazuk snapshots (1h, 4h)
        process_due(state, max_hours=4)
        # 2. naye phishunt (gap + B2)
        if picking:
            try:
                ph = fetch_phishunt(state)
                summary["phishunt_records"] = len(ph)
                pick_phishunt(state, ph, summary)
            except BudgetExhausted:
                raise
            except Exception as e:
                log_error(state, "phishunt", e)
        # 3. baqi snapshots (24h, 72h)
        process_due(state, min_hours=5)
        # 4. OpenPhish (control) + feed_seen
        try:
            update_openphish(state, fetch_openphish())
        except Exception as e:
            log_error(state, "openphish", e)
        if picking:
            pick_queue(state, "openphish", "openphish")
            # 5. benign B1 (Tranco)
            try:
                if time_left() > 300:          # bhari download; timeout ke qareeb mat shuru karo
                    tranco_new_entries(state)
            except Exception as e:
                log_error(state, "tranco", e)
            pick_queue(state, "benign_tranco", "benign")
    except BudgetExhausted as e:
        summary["budget"] = str(e)
        print(e)
    finally:
        retire_finished(state)
        if not picking and not state.get("active"):
            state["phase"] = "done"
        write_report(state)
        save_json(STATE_FILE, state)
        summary.update(active=len(state.get("active", {})), vt_today=vt_calls_today(state),
                       counts=state.get("counts", {}), seconds=round(time.time() - _run_started))
        append_jsonl(LOG_FILE, summary)
        print(json.dumps(summary))


if __name__ == "__main__":
    main()
