"""T-016B-2: controlled incremental merge vs same-time full truth. Scratch-only writes."""
import json,time,sys,hashlib,requests
from datetime import datetime,timezone
from collections import Counter,defaultdict
BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"; SLEEP=7.0
D=sys.argv[1]; S=requests.Session(); LOG=[]
plan=json.load(open(f"{D}/plan.json")); RULE=plan["rule"]
A={k:v for k,v in json.load(open(f"{D}/snapshot_a.json")).items()}
def canon(c): return hashlib.sha256(json.dumps(c,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
def get(p,l):
    t=time.perf_counter(); r=S.get(BASE,params=p,timeout=180); dt=time.perf_counter()-t
    time.sleep(SLEEP)
    d=r.json() if r.status_code==200 else None
    LOG.append({"label":l,"status":r.status_code,"total":d["totalResults"] if d else None,
                "returned":len(d.get("vulnerabilities",[])) if d else 0,"seconds":round(dt,2),
                "at":datetime.now(timezone.utc).isoformat()})
    print(f"  [{l}] total={d['totalResults'] if d else '-'} got={len(d.get('vulnerabilities',[])) if d else 0} {dt:.1f}s",flush=True)
    return d
def paged(params,label,cap=25):
    idx=0;rows=[];totals=[];pages=[]
    while True:
        d=get({**params,"resultsPerPage":2000,"startIndex":idx},f"{label}_p{idx}")
        if not d: return None,{"complete":False,"reason":"request failed"}
        n=len(d.get("vulnerabilities",[])); rows+=[v["cve"] for v in d.get("vulnerabilities",[])]
        totals.append(d["totalResults"]); pages.append({"startIndex":idx,"returned":n,"totalResults":d["totalResults"]})
        idx+=d["resultsPerPage"]
        if idx>=d["totalResults"] or d["resultsPerPage"]==0: break
        if len(pages)>cap: return None,{"complete":False,"reason":"page cap"}
    ids=[c["id"] for c in rows]; dup=[k for k,v in Counter(ids).items() if v>1]
    gate={"pages":len(pages),"first_total":totals[0],"last_total":totals[-1],
          "totals_equal":totals[0]==totals[-1],"fetched_rows":len(rows),
          "rows_match_total":len(rows)==totals[0],"duplicate_ids":len(dup),
          "complete":totals[0]==totals[-1] and len(rows)==totals[0] and not dup,
          "page_detail":pages}
    return rows,gate

R={"rule":RULE}
print("== 1. delta fetch (modified window) ==",flush=True)
T0=RULE["T0_used_for_delta"]; T1=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
R["T0"],R["T1"]=T0,T1
R["delta_fetch_started"]=datetime.now(timezone.utc).isoformat()
delta,dgate=paged({"lastModStartDate":T0,"lastModEndDate":T1},"delta")
R["delta_fetch_ended"]=datetime.now(timezone.utc).isoformat()
R["delta_gate"]=dgate
if not dgate["complete"]:
    R["stopped"]="delta window incomplete -> merge 금지"; json.dump(R,open(f"{D}/result.json","w"),indent=1,ensure_ascii=False); sys.exit(0)
json.dump({c["id"]:c for c in delta},open(f"{D}/delta.json","w"),ensure_ascii=False)

print("== 2. §30 published-partition 영향도 (전체 delta 기준) ==",flush=True)
def win(pub):  # configs/data.yaml 의 119일 window 경계 재현
    from datetime import date,timedelta
    cur=date(2020,1,1); p=date.fromisoformat(pub[:10])
    if p<cur: return "before-2020"
    while True:
        e=cur+timedelta(days=118)
        if cur<=p<=e: return f"{cur.isoformat()}_{e.isoformat()}"
        cur=e+timedelta(days=1)
by=Counter(win(c.get("published","")) for c in delta)
R["partition_impact"]={"delta_rows":len(delta),"affected_partitions":len(by),
    "rows_per_partition":dict(sorted(by.items())),
    "oldest_published_in_delta":min((c.get("published","") for c in delta),default=None),
    "newest_published_in_delta":max((c.get("published","") for c in delta),default=None)}

print("== 3. truth fetch (동일 published slice, 지금) ==",flush=True)
R["truth_fetch_started"]=datetime.now(timezone.utc).isoformat()
truth,tgate=paged({"pubStartDate":RULE["slice_published_start"]+"T00:00:00.000",
                   "pubEndDate":RULE["slice_published_end"]+"T23:59:59.999"},"truth")
R["truth_fetch_ended"]=datetime.now(timezone.utc).isoformat()
R["truth_gate"]=tgate
if not tgate["complete"]:
    R["stopped"]="truth window incomplete"; json.dump(R,open(f"{D}/result.json","w"),indent=1,ensure_ascii=False); sys.exit(0)
json.dump({c["id"]:c for c in truth},open(f"{D}/truth.json","w"),ensure_ascii=False)

print("== 4. merge (logical overlay) ==",flush=True)
lo,hi=RULE["slice_published_start"],RULE["slice_published_end"]
dslice={c["id"]:c for c in delta if lo<=str(c.get("published",""))[:10]<=hi}
def merge(base,dl):
    out=dict(base); stat=Counter(); conflicts=[]
    for i,c in dl.items():
        if i not in out: out[i]=c; stat["INSERT"]+=1
        elif canon(out[i])==canon(c): stat["NO_CONTENT_CHANGE"]+=1
        else:
            b,n=out[i].get("lastModified",""),c.get("lastModified","")
            if n>b: out[i]=c; stat["UPDATE"]+=1
            elif n==b: conflicts.append(i); stat["CONFLICT_REVIEW"]+=1
            else: stat["STALE_IGNORED"]+=1
    return out,stat,conflicts
M1,st1,cf1=merge(A,dslice)
M2,st2,cf2=merge(M1,dslice)   # idempotency: 같은 delta 재적용
R["merge"]={"delta_in_slice":len(dslice),"stats":dict(st1),"conflicts":cf1[:10],
            "idempotent_id_set":set(M1)==set(M2),
            "idempotent_canonical":all(canon(M1[i])==canon(M2[i]) for i in M1),
            "second_pass_stats":dict(st2)}

print("== 5. S0 equivalence ==",flush=True)
T={c["id"]:c for c in truth}
only_m=sorted(set(M1)-set(T)); only_t=sorted(set(T)-set(M1)); both=set(M1)&set(T)
mis=[i for i in both if canon(M1[i])!=canon(T[i])]
FIELDS=["published","descriptions","vulnStatus","weaknesses","cisaExploitAdd"]
def fh(c,f): return hashlib.sha256(json.dumps(c.get(f),sort_keys=True,ensure_ascii=False).encode()).hexdigest()
rel=[i for i in both if any(fh(M1[i],f)!=fh(T[i],f) for f in FIELDS)]
lm=[i for i in both if M1[i].get("lastModified")!=T[i].get("lastModified")]
# drift 판별: mismatch row의 truth lastModified가 delta fetch 종료 이후인가
drift=[i for i in mis if T[i].get("lastModified","")>=R["delta_fetch_ended"][:23]]
R["S0"]={"merged_n":len(M1),"truth_n":len(T),
  "id_symmetric_difference":len(only_m)+len(only_t),"only_in_merged":only_m[:10],"only_in_truth":only_t[:10],
  "canonical_mismatch":len(mis),"canonical_mismatch_sample":mis[:10],
  "dataset_relevant_field_mismatch":len(rel),"dataset_relevant_sample":rel[:10],
  "lastModified_mismatch":len(lm),
  "rejected_mismatch":sum(1 for i in both if (M1[i].get("vulnStatus")=="Rejected")!=(T[i].get("vulnStatus")=="Rejected")),
  "kev_mismatch":sum(1 for i in both if bool(M1[i].get("cisaExploitAdd"))!=bool(T[i].get("cisaExploitAdd"))),
  "mismatch_explained_by_drift_after_delta":len(drift),"drift_sample":drift[:10]}
if len(only_m)+len(only_t)==0 and not mis: v="PASS"
elif mis and len(drift)==len(mis): v="INCONCLUSIVE_API_DRIFT"
elif cf1: v="CONFLICT_REVIEW"
else: v="FAIL"
R["S0"]["verdict"]=v
R["_log"]=LOG; R["_requests"]=len(LOG)
json.dump(R,open(f"{D}/result.json","w"),indent=1,ensure_ascii=False)
print(f"\nS0 판정: {v} | 요청 {len(LOG)}건",flush=True)
