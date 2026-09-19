"""T-016B probe 3: pagination completeness on a window known to be non-empty (489 records)."""
import json,time,sys,requests
from collections import Counter
BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"; SLEEP=7.0
S=requests.Session(); OUT=sys.argv[1]; LOG=[]
W0,W1="2026-09-17T16:48:55.000","2026-09-17T17:18:55.000"   # probe2 BC: 489건
def get(p,l):
    r=S.get(BASE,params=p,timeout=120); time.sleep(SLEEP)
    d=r.json() if r.status_code==200 else None
    LOG.append({"label":l,"status":r.status_code,"total":d["totalResults"] if d else None,
                "returned":len(d.get("vulnerabilities",[])) if d else 0,"startIndex":d["startIndex"] if d else None})
    print(f"  [{l}] total={d['totalResults'] if d else '-'} returned={len(d.get('vulnerabilities',[])) if d else 0} startIndex={d['startIndex'] if d else '-'}",flush=True)
    return d
print("== pagination 끝까지 (resultsPerPage=200) ==",flush=True)
per=200; idx=0; rows=0; totals=[]; ids=[]; pages=[]
while True:
    d=get({"lastModStartDate":W0,"lastModEndDate":W1,"resultsPerPage":per,"startIndex":idx},f"pg{idx}")
    if not d: break
    n=len(d.get("vulnerabilities",[])); rows+=n; totals.append(d["totalResults"])
    ids+=[v["cve"]["id"] for v in d.get("vulnerabilities",[])]
    pages.append({"startIndex":idx,"returned":n,"resultsPerPage":d["resultsPerPage"],"totalResults":d["totalResults"]})
    idx+=d["resultsPerPage"]
    if idx>=d["totalResults"] or d["resultsPerPage"]==0: break
    if len(pages)>15: break
dup=[k for k,v in Counter(ids).items() if v>1]
# 단일 요청으로 전량 가져와 비교
full=get({"lastModStartDate":W0,"lastModEndDate":W1,"resultsPerPage":2000},"single_full")
fids=[v["cve"]["id"] for v in (full or {}).get("vulnerabilities",[])]
R={"window":[W0,W1],"per_page":per,"pages":pages,"summed_rows":rows,
   "totals_seen":sorted(set(totals)),"totalResults_stable":len(set(totals))<=1,
   "rows_match_total":bool(totals) and rows==totals[0],
   "completed_pagination":bool(totals) and idx>=totals[0],
   "unique_ids":len(set(ids)),"duplicate_ids_across_pages":len(dup),"dup_sample":dup[:5],
   "single_request_total":full["totalResults"] if full else None,
   "paged_set_equals_single_set":set(ids)==set(fids),
   "paged_order_equals_single_order":ids==fids,
   "_log":LOG}
json.dump(R,open(OUT,"w"),indent=1,ensure_ascii=False)
print(f"\n요청 {len(LOG)}건 -> {OUT}",flush=True)
