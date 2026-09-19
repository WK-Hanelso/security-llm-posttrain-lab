"""T-016C: silent-drift accumulation over the one measurable reconciliation gap."""
import json,time,sys,hashlib,requests
from datetime import datetime,timezone
from collections import Counter
sys.path.insert(0,"src")
from security_llm.config import load_config
from security_llm.data.normalize import normalize_record
BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"; SLEEP=7.0
D=sys.argv[1]; S=requests.Session(); LOG=[]
CFG=load_config("configs/data.yaml",[])
LO,HI="2026-07-08","2026-09-17"
T0="2026-09-17T00:00:00.000"
def canon(c): return hashlib.sha256(json.dumps(c,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
def get(p,l):
    t=time.perf_counter(); r=S.get(BASE,params=p,timeout=180); dt=time.perf_counter()-t; time.sleep(SLEEP)
    d=r.json() if r.status_code==200 else None
    LOG.append({"label":l,"status":r.status_code,"total":d["totalResults"] if d else None,
                "returned":len(d.get("vulnerabilities",[])) if d else 0,"seconds":round(dt,2)})
    print(f"  [{l}] total={d['totalResults'] if d else '-'} got={len(d.get('vulnerabilities',[])) if d else 0} {dt:.1f}s",flush=True)
    return d
def paged(params,label,cap=40):
    idx=0;rows=[];totals=[];pages=0
    while True:
        d=get({**params,"resultsPerPage":2000,"startIndex":idx},f"{label}_p{idx}")
        if not d: return None,{"complete":False,"reason":"request failed"}
        rows+=[v["cve"] for v in d.get("vulnerabilities",[])]; totals.append(d["totalResults"]); pages+=1
        idx+=d["resultsPerPage"]
        if idx>=d["totalResults"] or d["resultsPerPage"]==0: break
        if pages>cap: return None,{"complete":False,"reason":"page cap"}
    ids=[c["id"] for c in rows]; dup=[k for k,v in Counter(ids).items() if v>1]
    g={"pages":pages,"first_total":totals[0],"last_total":totals[-1],"totals_equal":totals[0]==totals[-1],
       "fetched_rows":len(rows),"rows_match_total":len(rows)==totals[0],"duplicate_ids":len(dup)}
    g["complete"]=g["totals_equal"] and g["rows_match_total"] and not dup
    return rows,g

base=json.load(open(f"{D}/baseline.json"))
R={"population":"published %s..%s"%(LO,HI),"baseline_rows":len(base),"T0":T0,
   "gap_note":"단일 측정 gap. historical full snapshot이 1개뿐이라 1d/3d/7d 비교 불가 (SPEC §39 Case C)."}
print("== delta fetch ==",flush=True)
T1=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"); R["T1"]=T1
R["gap_hours"]=round((datetime.fromisoformat(T1)-datetime.fromisoformat(T0)).total_seconds()/3600,2)
R["delta_started"]=datetime.now(timezone.utc).isoformat()
delta,dg=paged({"lastModStartDate":T0,"lastModEndDate":T1},"delta")
R["delta_ended"]=datetime.now(timezone.utc).isoformat(); R["delta_gate"]=dg
if not dg["complete"]:
    R["stopped"]="delta incomplete"; json.dump(R,open(f"{D}/result.json","w"),indent=1,ensure_ascii=False); sys.exit(0)
print("== truth fetch ==",flush=True)
R["truth_started"]=datetime.now(timezone.utc).isoformat()
truth,tg=paged({"pubStartDate":LO+"T00:00:00.000","pubEndDate":HI+"T23:59:59.999"},"truth")
R["truth_ended"]=datetime.now(timezone.utc).isoformat(); R["truth_gate"]=tg
if not tg["complete"]:
    R["stopped"]="truth incomplete"; json.dump(R,open(f"{D}/result.json","w"),indent=1,ensure_ascii=False); sys.exit(0)

print("== overlay merge ==",flush=True)
dsl={c["id"]:c for c in delta if LO<=str(c.get("published",""))[:10]<=HI}
M=dict(base); st=Counter(); conf=[]
for i,c in dsl.items():
    if i not in M: M[i]=c; st["INSERT"]+=1
    elif canon(M[i])==canon(c): st["NO_CONTENT_CHANGE"]+=1
    else:
        b,n=M[i].get("lastModified",""),c.get("lastModified","")
        if n>b: M[i]=c; st["UPDATE"]+=1
        elif n==b: conf.append(i); st["CONFLICT_REVIEW"]+=1
        else: st["STALE_IGNORED"]+=1
M2=dict(M)
for i,c in dsl.items():
    if i in M2 and canon(M2[i])!=canon(c) and c.get("lastModified","")>M2[i].get("lastModified",""): M2[i]=c
R["overlay"]={"delta_rows":len(delta),"delta_in_population":len(dsl),"stats":dict(st),"conflicts":conf[:10],
              "idempotent":all(canon(M[i])==canon(M2[i]) for i in M) and set(M)==set(M2)}

print("== D0 / D1 / D2 ==",flush=True)
T={c["id"]:c for c in truth}
both=set(M)&set(T); only_m=sorted(set(M)-set(T)); only_t=sorted(set(T)-set(M))
D0=[i for i in both if canon(M[i])!=canon(T[i])]
FIELDS=["id","published","descriptions","vulnStatus","weaknesses","cisaExploitAdd"]
def fh(c,f): return hashlib.sha256(json.dumps(c.get(f),sort_keys=True,ensure_ascii=False).encode()).hexdigest()
D1=[i for i in D0 if any(fh(M[i],f)!=fh(T[i],f) for f in FIELDS)]
# D2: 실제 pipeline normalize_record 로 composition 구동 필드 비교
COMP=["is_rejected","label_status","cwe_id","published","description_norm_hash","cwe_all"]
D2=[]; d2det=[]
for i in D1:
    a=normalize_record(M[i],CFG); b=normalize_record(T[i],CFG)
    if a is None or b is None: D2.append(i); d2det.append({"cve":i,"reason":"normalize returned None"}); continue
    diff=[k for k in COMP if json.dumps(a.get(k),sort_keys=True)!=json.dumps(b.get(k),sort_keys=True)]
    if diff: D2.append(i); d2det.append({"cve":i,"fields":diff,
        "before":{k:a.get(k) for k in diff},"after":{k:b.get(k) for k in diff}})
def cls(i):
    ch=[f for f in FIELDS if fh(M[i],f)!=fh(T[i],f)]
    if not ch: return "dataset_irrelevant"
    if len(ch)>1: return "multiple_fields"
    f=ch[0]
    if f=="vulnStatus":
        return "rejected_transition" if (M[i].get("vulnStatus")=="Rejected")!=(T[i].get("vulnStatus")=="Rejected") else "vulnStatus"
    return {"descriptions":"description","weaknesses":"weakness","cisaExploitAdd":"KEV","published":"published"}.get(f,f)
R["drift"]={"population":len(both),"id_only_in_incremental":len(only_m),"id_only_in_truth":len(only_t),
  "only_in_truth_sample":only_t[:5],
  "D0_count":len(D0),"D0_rate_pct":round(len(D0)/len(both)*100,4),
  "D1_count":len(D1),"D1_rate_pct":round(len(D1)/len(both)*100,4),
  "D2_count":len(D2),"D2_rate_pct":round(len(D2)/len(both)*100,4),
  "classification":dict(Counter(cls(i) for i in D0)),
  "lastModified_identical_among_D0":sum(1 for i in D0 if M[i].get("lastModified")==T[i].get("lastModified")),
  "D2_detail":d2det[:20],"D0_sample":D0[:10]}
R["reconciliation_corrections"]={"rows_a_full_fetch_would_replace":len(D0),
  "dataset_relevant_corrections":len(D1),"composition_corrections":len(D2),
  "new_ids_recovered":len(only_t)}
R["cost"]={"delta_requests":sum(1 for l in LOG if l["label"].startswith("delta")),
  "truth_requests":sum(1 for l in LOG if l["label"].startswith("truth")),
  "delta_rows":len(delta),"truth_rows":len(truth),
  "delta_wall_s":round((datetime.fromisoformat(R["delta_ended"])-datetime.fromisoformat(R["delta_started"])).total_seconds(),1),
  "truth_wall_s":round((datetime.fromisoformat(R["truth_ended"])-datetime.fromisoformat(R["truth_started"])).total_seconds(),1),
  "note":"truth = 이 published window 1개만. 전체 full ingest(2~2.5h)가 아님"}
R["_log"]=LOG
json.dump(R,open(f"{D}/result.json","w"),indent=1,ensure_ascii=False)
print(f"\nD0={len(D0)} D1={len(D1)} D2={len(D2)} / population {len(both)} | 요청 {len(LOG)}건",flush=True)
