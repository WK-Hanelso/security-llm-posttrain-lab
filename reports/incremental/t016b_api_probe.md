# T-016B — NVD API behaviour probe results

Run 2026-09-20 from the orchestrator shell, no API key, 7 s between requests (official guidance
is at least 6 s). 32 requests across three probe scripts. Read-only: nothing in the repository's
protected paths or existing manifests was written; raw results are
`t016b_probe{1,2,3}.json`.

No fetcher was built. This characterizes API behaviour only.

Anchor record: `CVE-2021-44228`, `lastModified = 2026-08-11T19:33:44.513`.

## Status of the eleven required items

| # | Item | Status | Finding |
|---|---|---|---|
| 1 | start boundary | **confirmed** | **inclusive** |
| 2 | end boundary | **confirmed** | **exclusive** |
| 3 | timestamp precision | **confirmed** | millisecond precision is honoured |
| 4 | timezone equivalence | **confirmed** | no-zone treated as UTC; `Z`, `+00:00` and a shifted `-04:00` all equivalent |
| 5 | adjacent-window duplicate | *observed only* | intersection 0 with both windows non-empty — but no record sat exactly on the shared boundary, so that case is untested |
| 6 | result ordering | *observed only* | stable across repeats and identical between paged and single-request; no guarantee established |
| 7 | new CVE inclusion | **confirmed** | newly published CVEs do appear in a lastMod query |
| 8 | rejected inclusion | **confirmed** | `Rejected` records returned by default |
| 9 | pagination completeness | **confirmed** | summed rows equal `totalResults` exactly |
| 10 | totalResults stability | *observed only* | stable within each short run; nothing shown about concurrent updates |
| 11 | identical-window idempotency | **confirmed** | ID set, canonical hashes and order all identical |

Nothing is left wholly unresolved, but items 5, 6 and 10 are observations, not guarantees, and
are **not** to be relied on in design.

## 1–2. The boundary is half-open, `[start, end)`

| Window | `totalResults` | anchor present |
|---|---:|---|
| `[T, T]` | 0 | no |
| `[T, T+1ms]` | 139 | **yes** |
| `[T-1ms, T]` | 0 | no |
| `[T+1ms, T+2ms]` | 0 | no |
| `[T-2ms, T-1ms]` | 0 | no |

The anchor is returned when its timestamp is the **start** and not when it is the **end**.

**Consequence.** NVD's recommended workflow — set the next `lastModStartDate` to the timestamp
of the last record received — re-returns that record once and omits nothing. The common
"optimisation" of starting one millisecond later omits every record sharing that exact
millisecond.

How many records that can be is not constant. In an ordinary hour, 490 records carried 490
distinct timestamps, at most one per millisecond. But the anchor's own millisecond was shared
by **139 records**, from what looks like a bulk re-analysis. So the risk is episodic and
largest precisely during bulk events, which is when omission would matter most.

Overlap is therefore not required for correctness if the start is set to the last record's
timestamp exactly. Overlap remains cheap insurance and stays in the design; what changed is
that the argument for it is now quantified rather than assumed.

## 3–4. Timestamps

Four spellings of the same instant returned identical results, anchor present in each:
`…44.512` / `…44.512Z` / `…44.512+00:00` / `2026-08-11T15:33:44.512-04:00`. A zone-less
timestamp is treated as UTC and offset arithmetic is applied correctly. Millisecond precision
is real: `T`, `T±1ms` and `T±2ms` produce different result sets.

## 5. Adjacent windows

`[A, B]` returned 1 record and `[B, C]` returned 489, so both were non-empty, and the
intersection was empty. Consistent with the half-open interval.

**The weak point is explicit**: no record had `lastModified` exactly equal to `B`, so what
happens to a record sitting on a shared boundary was not exercised. Earlier a similar test was
worthless because one window was empty; this one is better but still does not settle the case.

## 6. Ordering

Two identical requests returned the same 139 IDs in the same order, and a three-page paged read
returned the same order as a single-request read of the same window. Both are observations.
The apparent sort in probe 1 was vacuous — all 139 records shared one `lastModified`, so the
sequence was trivially both ascending and descending. **Design must not assume ordering.**

## 7–8. Content of a lastMod window

A two-hour recent window returned 672 records: 481 published within the previous three days, so
new publications do surface through `lastModified`; 2 records with `vulnStatus = Rejected`
without `noRejected`, confirming rejected records are included by default. Seven statuses were
present: Analyzed, Awaiting Analysis, Deferred, Modified, Received, Rejected, Undergoing
Analysis.

## 9–10. Pagination and the real completeness condition

A 489-record window at `resultsPerPage=200`:

| startIndex | returned | totalResults |
|---:|---:|---:|
| 0 | 200 | 489 |
| 200 | 200 | 489 |
| 400 | 89 | 489 |

Summed rows 489, exactly `totalResults`. No duplicate IDs across pages. The paged result set
**and its order** matched a single-request read of the same window.

**This settles what replaces the hardcoded flag.** `docs/INGEST_SEMANTICS.md` §1.1 records that
`ingest_nvd.py` appends `"complete": True` as a literal and that `normalize()` gates on exactly
that field, so the gate cannot fail. The condition it should assert is

```
sum(len(page["vulnerabilities"]) for page in window) == totalResults
```

together with `totalResults` being identical on every page of the window. Both were verified
here.

`totalResults` stability is *observed only*: it held across every run, but no run overlapped a
concurrent update, so nothing is shown about drift during a long fetch. A real ingester must
still compare the first and last page's `totalResults` and reject the window on disagreement.

## 11. Idempotency

The same window fetched twice gave the same ID set, identical canonical per-record hashes, and
identical ordering. Repeating a window is a no-op at the API level.

## What this does not establish

No deletion signal was looked for or found; `MISSING` remains distinct from `DELETE`. Behaviour
under concurrent modification, over long multi-window runs, with an API key's higher rate limit,
or during an NVD incident like the 2025 `lastModStartDate` advisory, is untested. Items 5, 6
and 10 stay observations.
