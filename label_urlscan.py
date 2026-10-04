#!/usr/bin/env python3
"""
Pilot 2 ke urlscan URLs ka ground-truth check (ek dafa chalne wali script).

Har urlscan URL ke liye urlscan.io ka apna scan result parhta hai (Result API, free plan
mein allowed; search ki tarah verdicts par pabandi nahi), aur ye nikalta hai:
  - urlscan ka verdict (malicious? score, brands, categories)
  - page ka title aur final URL (manual check mein madad ke liye)
Kuch bhi scan/submit NAHI karta. VirusTotal ko bhi nahi chhoota.

Output (private data repo mein):
  pilot2/urlscan_labels.jsonl  - har URL ki ek line
  pilot2/urlscan_labels.md     - khulasa + manual check ke liye table
"""

import json
import os
import sys
import time
from pathlib import Path

import requests

URLSCAN_KEY = os.environ.get("URLSCAN_API_KEY", "")
DATA_DIR = Path(os.environ.get("DATA_DIR", "data")) / "pilot2"
STATE_FILE = DATA_DIR / "state.json"
OBS_FILE = DATA_DIR / "observations.jsonl"
OUT_JSONL = DATA_DIR / "urlscan_labels.jsonl"
OUT_MD = DATA_DIR / "urlscan_labels.md"
RESULT_API = "https://urlscan.io/api/v1/result/{}/"
GAP_SECONDS = 1.5          # free quota: 120 result reads/minute; hum bahut neeche hain


def fetch(uuid):
    err = "failed"
    for attempt in range(3):
        try:
            r = requests.get(RESULT_API.format(uuid), headers={"API-Key": URLSCAN_KEY}, timeout=60)
        except requests.RequestException as e:
            err = str(e)[:150]
            time.sleep(10 * (attempt + 1))
            continue
        if r.status_code == 429:
            time.sleep(60)
            continue
        if r.status_code != 200:
            return {"http_status": r.status_code}
        return r.json()
    return {"error": err}


def summarize(js):
    if "http_status" in js or "error" in js:
        return {"ok": False, **js}
    v = js.get("verdicts", {}) or {}
    ov = v.get("overall", {}) or {}
    us = v.get("urlscan", {}) or {}
    eng = v.get("engines", {}) or {}
    page = js.get("page", {}) or {}
    return {
        "ok": True,
        "malicious": ov.get("malicious"),
        "score": ov.get("score"),
        "brands": ov.get("brands") or us.get("brands") or [],
        "categories": ov.get("categories") or [],
        "engines_malicious": eng.get("maliciousTotal"),
        "title": (page.get("title") or "")[:120],
        "final_url": (page.get("url") or "")[:200],
        "page_status": page.get("status"),
    }


def mal(o):
    return (o.get("stats") or {}).get("malicious", 0) if o and o.get("state") == "found" else 0


def main():
    if not URLSCAN_KEY:
        sys.exit("URLSCAN_API_KEY secret nahi mila.")
    state = json.loads(STATE_FILE.read_text())
    obs = [json.loads(l) for l in OBS_FILE.read_text().splitlines() if l.strip()]
    t0 = {o["url"]: o for o in obs if o["kind"] == "t0"}
    rc = {o["url"]: o for o in obs if o["kind"] == "recheck"}

    recs = [r for r in state.get("urls", []) if r["source"] == "urlscan"]
    out = []
    for r in recs:
        uuid = (r.get("meta") or {}).get("urlscan_id")
        s = summarize(fetch(uuid)) if uuid else {"ok": False, "error": "no urlscan_id"}
        row = {"url": r["url"], "urlscan_id": uuid,
               "vt_t0_state": (t0.get(r["url"]) or {}).get("state"),
               "vt_t0_malicious": mal(t0.get(r["url"])),
               "vt_24h_malicious": mal(rc.get(r["url"])), **s}
        out.append(row)
        time.sleep(GAP_SECONDS)

    OUT_JSONL.write_text("\n".join(json.dumps(x) for x in out) + "\n")

    ok = [x for x in out if x.get("ok")]
    m = [x for x in ok if x.get("malicious")]
    branded = [x for x in ok if x.get("brands")]
    m_vt_unknown = [x for x in m if x["vt_t0_state"] == "unknown"]
    lines = [
        "# urlscan URLs: kitne asal phishing hain?", "",
        f"Kul urlscan URLs: {len(out)} | Result mila: {len(ok)}", "",
        "| Sawaal | Jawab |", "|---|---|",
        f"| urlscan ne malicious kaha | {len(m)}/{len(ok)} |",
        f"| urlscan ne koi brand pehchana (impersonation) | {len(branded)}/{len(ok)} |",
        f"| urlscan: malicious, lekin VT ko t0 par pata hi nahi tha | {len(m_vt_unknown)}/{len(m)} |",
        f"| un mein se 24h baad bhi VT 5+ par | {sum(x['vt_24h_malicious'] >= 5 for x in m_vt_unknown)}/{len(m_vt_unknown)} |",
        "", "**Note:** urlscan ka verdict bhi ek TI hai, ground truth nahi. Asal label manual check se banega "
        "(neeche table; screenshot urlscan.io/result/<id> par, apne browser mein phishing page mat kholein).", "",
        "## Manual check ke liye", "",
        "| # | urlscan verdict | Score | Brands | Title | VT t0 | VT 24h | urlscan result |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, x in enumerate(out, 1):
        verdict = "malicious" if x.get("malicious") else ("-" if not x.get("ok") else "clean/none")
        title = (x.get("title") or "").replace("|", "/")
        lines.append(f"| {i} | {verdict} | {x.get('score', '-')} | {', '.join(map(str, x.get('brands') or []))[:40]} | "
                     f"{title[:60]} | {x['vt_t0_state']} ({x['vt_t0_malicious']}) | {x['vt_24h_malicious']} | "
                     f"https://urlscan.io/result/{x['urlscan_id']}/ |")
    OUT_MD.write_text("\n".join(lines) + "\n")
    print(f"Done: {len(ok)}/{len(out)} results, malicious {len(m)}, branded {len(branded)}")


if __name__ == "__main__":
    main()
