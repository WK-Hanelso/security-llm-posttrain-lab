"""T-016B — NVD API behaviour characterization probes. Read-only; writes to scratch only."""
import json, time, hashlib, sys
from datetime import datetime, timedelta, timezone
import requests

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SLEEP = 7.0                      # no API key: official guidance is >= 6 s between requests
OUT = sys.argv[1]
S = requests.Session()
LOG = []

def get(params, label):
    t0 = time.perf_counter()
    r = S.get(BASE, params=params, timeout=120)
    dt = time.perf_counter() - t0
    time.sleep(SLEEP)
    rec = {"label": label, "params": dict(params), "status": r.status_code, "seconds": round(dt, 2)}
    if r.status_code != 200:
        rec["body"] = r.text[:300]; LOG.append(rec); return rec, None
    d = r.json()
    ids = [v["cve"]["id"] for v in d.get("vulnerabilities", [])]
    rec.update(totalResults=d["totalResults"], resultsPerPage=d["resultsPerPage"],
               startIndex=d["startIndex"], returned=len(ids), ids_head=ids[:5])
    LOG.append(rec)
    print(f"  [{label}] status={r.status_code} total={d['totalResults']} returned={len(ids)} {dt:.1f}s", flush=True)
    return rec, d

def canon(cve):
    return hashlib.sha256(json.dumps(cve, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

R = {}
ANCHOR = "CVE-2021-44228"
T = "2026-08-11T19:33:44.513"
def shift(ts, ms):
    dt = datetime.fromisoformat(ts) + timedelta(milliseconds=ms)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond//1000:03d}"

print("== 1. boundary ==", flush=True)
R["boundary"] = {}
for name, s, e in [("A_TT", T, T),
                   ("B_T_to_Tplus1", T, shift(T, 1)),
                   ("C_Tminus1_to_T", shift(T, -1), T),
                   ("D_after", shift(T, 1), shift(T, 2)),
                   ("E_before", shift(T, -2), shift(T, -1))]:
    rec, d = get({"lastModStartDate": s, "lastModEndDate": e, "resultsPerPage": 200}, name)
    hit = bool(d) and any(v["cve"]["id"] == ANCHOR for v in d.get("vulnerabilities", []))
    R["boundary"][name] = {"start": s, "end": e, "anchor_present": hit,
                           "total": rec.get("totalResults"), "status": rec["status"]}

print("== 2. timestamp format / timezone ==", flush=True)
R["timestamp"] = {}
W0, W1 = shift(T, -1), shift(T, 1)
for name, s, e in [("plain", W0, W1),
                   ("Z", W0 + "Z", W1 + "Z"),
                   ("utc_offset", W0 + "+00:00", W1 + "+00:00"),
                   ("shifted_offset", shift(T, -1 - 4*3600*1000) + "-04:00", shift(T, 1 - 4*3600*1000) + "-04:00")]:
    rec, d = get({"lastModStartDate": s, "lastModEndDate": e, "resultsPerPage": 200}, name)
    R["timestamp"][name] = {"start": s, "end": e, "status": rec["status"],
                            "total": rec.get("totalResults"),
                            "anchor_present": bool(d) and any(v["cve"]["id"] == ANCHOR for v in d.get("vulnerabilities", []))}

print("== 3. adjacent windows ==", flush=True)
A, B, C = shift(T, -60000), shift(T, 0), shift(T, 60000)   # +-60 s around T
sets = {}
for name, s, e in [("AB", A, B), ("BC", B, C), ("overlap", shift(T, -1000), shift(T, 1000))]:
    rec, d = get({"lastModStartDate": s, "lastModEndDate": e, "resultsPerPage": 2000}, name)
    sets[name] = {v["cve"]["id"] for v in d.get("vulnerabilities", [])} if d else set()
R["adjacent"] = {"AB_total": len(sets["AB"]), "BC_total": len(sets["BC"]),
                 "intersection": sorted(sets["AB"] & sets["BC"]),
                 "intersection_size": len(sets["AB"] & sets["BC"]),
                 "windows": {"A": A, "B": B, "C": C}}

print("== 4. ordering (same request twice) ==", flush=True)
ordp = {"lastModStartDate": A, "lastModEndDate": C, "resultsPerPage": 2000}
_, d1 = get(ordp, "order_1")
_, d2 = get(ordp, "order_2")
ids1 = [v["cve"]["id"] for v in d1.get("vulnerabilities", [])] if d1 else []
ids2 = [v["cve"]["id"] for v in d2.get("vulnerabilities", [])] if d2 else []
lm1 = [v["cve"]["lastModified"] for v in d1.get("vulnerabilities", [])] if d1 else []
R["ordering"] = {"n": len(ids1), "identical_order": ids1 == ids2,
                 "same_set": set(ids1) == set(ids2),
                 "lastmod_sorted_asc": lm1 == sorted(lm1),
                 "lastmod_sorted_desc": lm1 == sorted(lm1, reverse=True),
                 "head": ids1[:5]}

print("== 5/6. rejected + new-CVE inclusion (recent window) ==", flush=True)
now = datetime.now(timezone.utc)
rs = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000")
re_ = (now - timedelta(days=2) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000")
rec, d = get({"lastModStartDate": rs, "lastModEndDate": re_, "resultsPerPage": 2000}, "recent_window")
vs = d.get("vulnerabilities", []) if d else []
rejected = [v["cve"]["id"] for v in vs if v["cve"].get("vulnStatus") == "Rejected"]
newly = [v["cve"]["id"] for v in vs if v["cve"].get("published", "")[:10] >= (now - timedelta(days=3)).strftime("%Y-%m-%d")]
R["recent_window"] = {"window": [rs, re_], "total": rec.get("totalResults"), "returned": len(vs),
                      "rejected_count": len(rejected), "rejected_sample": rejected[:5],
                      "newly_published_in_window": len(newly), "newly_sample": newly[:5],
                      "statuses": sorted({v["cve"].get("vulnStatus") for v in vs})}

print("== 7. pagination + totalResults stability ==", flush=True)
pag = {"lastModStartDate": rs, "lastModEndDate": re_, "resultsPerPage": 20}
pages, rows, totals = [], 0, []
idx = 0
for _ in range(6):
    rec, d = get({**pag, "startIndex": idx}, f"page_{idx}")
    if not d: break
    n = len(d.get("vulnerabilities", []))
    pages.append({"startIndex": idx, "returned": n, "totalResults": d["totalResults"], "resultsPerPage": d["resultsPerPage"]})
    totals.append(d["totalResults"]); rows += n
    idx += d["resultsPerPage"]
    if idx >= d["totalResults"] or d["resultsPerPage"] == 0: break
R["pagination"] = {"pages": pages, "summed_rows": rows, "totals_seen": totals,
                   "totalResults_stable": len(set(totals)) <= 1,
                   "rows_match_total": bool(totals) and rows == totals[0],
                   "last_startIndex": idx}

print("== 8. idempotency (same window twice) ==", flush=True)
idem = {"lastModStartDate": A, "lastModEndDate": C, "resultsPerPage": 2000}
_, e1 = get(idem, "idem_1")
_, e2 = get(idem, "idem_2")
def cmap(d): return {v["cve"]["id"]: canon(v["cve"]) for v in d.get("vulnerabilities", [])} if d else {}
m1, m2 = cmap(e1), cmap(e2)
diff = [k for k in m1 if m1[k] != m2.get(k)]
R["idempotency"] = {"n1": len(m1), "n2": len(m2), "id_set_equal": set(m1) == set(m2),
                    "canonical_hash_differs_for": diff[:5], "canonical_all_equal": not diff,
                    "order_identical": [v["cve"]["id"] for v in (e1 or {}).get("vulnerabilities", [])]
                                       == [v["cve"]["id"] for v in (e2 or {}).get("vulnerabilities", [])]}

R["_meta"] = {"anchor": ANCHOR, "anchor_lastModified": T, "sleep_seconds": SLEEP,
              "requests": len(LOG), "api_key_used": False,
              "run_at_utc": datetime.now(timezone.utc).isoformat()}
R["_request_log"] = LOG
with open(OUT, "w") as f: json.dump(R, f, indent=1, ensure_ascii=False)
print(f"\n총 요청 {len(LOG)}건 -> {OUT}", flush=True)
