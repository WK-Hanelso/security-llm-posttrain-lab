"""T-016B follow-up: close pagination completeness and adjacent-duplicate with non-empty windows."""
import json, time, hashlib, sys
from datetime import datetime, timedelta, timezone
import requests
BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"; SLEEP=7.0
S=requests.Session(); LOG=[]; OUT=sys.argv[1]
def get(p,label):
    r=S.get(BASE,params=p,timeout=120); time.sleep(SLEEP)
    d=r.json() if r.status_code==200 else None
    LOG.append({"label":label,"params":dict(p),"status":r.status_code,
                "total":d["totalResults"] if d else None,"returned":len(d.get("vulnerabilities",[])) if d else 0})
    print(f"  [{label}] total={d['totalResults'] if d else '-'} returned={len(d.get('vulnerabilities',[])) if d else 0}",flush=True)
    return d
R={}
now=datetime.now(timezone.utc)
def ts(dt): return dt.strftime("%Y-%m-%dT%H:%M:%S.000")

# --- A. 작은 window를 끝까지 페이지네이션해서 완전성 조건 검증 ---
print("== A. pagination completeness (끝까지) ==",flush=True)
base=now-timedelta(days=2)
w0,w1=ts(base),ts(base+timedelta(minutes=10))
probe=get({"lastModStartDate":w0,"lastModEndDate":w1,"resultsPerPage":2000},"sizing")
N=probe["totalResults"] if probe else 0
per=20 if N<=200 else max(20,(N//5)+1)
pages=[];rows=0;totals=[];idx=0;ids=[]
while True:
    d=get({"lastModStartDate":w0,"lastModEndDate":w1,"resultsPerPage":per,"startIndex":idx},f"pg{idx}")
    if not d: break
    n=len(d.get("vulnerabilities",[])); rows+=n; totals.append(d["totalResults"])
    ids+= [v["cve"]["id"] for v in d.get("vulnerabilities",[])]
    pages.append({"startIndex":idx,"returned":n,"resultsPerPage":d["resultsPerPage"],"totalResults":d["totalResults"]})
    idx+=d["resultsPerPage"]
    if idx>=d["totalResults"] or d["resultsPerPage"]==0: break
    if len(pages)>25: break
R["pagination_full"]={"window":[w0,w1],"per_page":per,"pages":pages,"summed_rows":rows,
    "totals_seen":sorted(set(totals)),"totalResults_stable":len(set(totals))<=1,
    "rows_match_total":bool(totals) and rows==totals[0],
    "unique_ids":len(set(ids)),"duplicate_ids_across_pages":len(ids)-len(set(ids)),
    "completed_pagination":bool(totals) and idx>=totals[0]}

# --- B. 양쪽이 모두 비지 않은 인접 window 교집합 ---
print("== B. adjacent (양쪽 non-empty) ==",flush=True)
A=ts(base); B=ts(base+timedelta(minutes=30)); C=ts(base+timedelta(minutes=60))
dab=get({"lastModStartDate":A,"lastModEndDate":B,"resultsPerPage":2000},"AB")
dbc=get({"lastModStartDate":B,"lastModEndDate":C,"resultsPerPage":2000},"BC")
sa={v["cve"]["id"] for v in (dab or {}).get("vulnerabilities",[])}
sb={v["cve"]["id"] for v in (dbc or {}).get("vulnerabilities",[])}
# B 경계 시각을 정확히 가진 레코드가 있는지
at_b=[v["cve"]["id"] for v in (dbc or {}).get("vulnerabilities",[]) if v["cve"]["lastModified"]==B.replace(".000",".000")]
R["adjacent_nonempty"]={"A":A,"B":B,"C":C,"AB_n":len(sa),"BC_n":len(sb),
    "both_nonempty":bool(sa) and bool(sb),"intersection_size":len(sa&sb),
    "intersection_sample":sorted(sa&sb)[:5],
    "records_exactly_at_boundary_B":len(at_b)}

# --- C. 동일 밀리초 공유 레코드 수 분포 (누락 위험 정량화) ---
print("== C. 같은 ms 공유 레코드 ==",flush=True)
d=get({"lastModStartDate":A,"lastModEndDate":C,"resultsPerPage":2000},"ms_dist")
from collections import Counter
c=Counter(v["cve"]["lastModified"] for v in (d or {}).get("vulnerabilities",[]))
top=c.most_common(5)
R["same_millisecond"]={"window":[A,C],"n_records":sum(c.values()),"distinct_timestamps":len(c),
    "max_sharing_one_ms":top[0][1] if top else 0,"top5":top}
R["_meta"]={"sleep":SLEEP,"requests":len(LOG),"run_at_utc":now.isoformat(),"api_key_used":False}
R["_log"]=LOG
json.dump(R,open(OUT,"w"),indent=1,ensure_ascii=False)
print(f"\n요청 {len(LOG)}건 -> {OUT}",flush=True)
