# T-016A — NVD incremental ingest semantics and equivalence specification

Specification for the incremental-ingest track. This document is the source of truth for what
the current ingester guarantees, what the NVD API is documented to guarantee, and what must be
established before any incremental fetcher is written.

Status: v1 (2026-09-20). Base commit `a4bad58`. T-014 and the T-015 downstream track are
closed; their artifacts and `main` at v0.1.0 are frozen inputs.

T-015 concluded that downstream stays a deterministic full rebuild. This track targets the
only real cost: **ingestion at 2 to 2.5 hours against 56 seconds of downstream work.**

The question is not "is fetching less faster". It is:

> Does a snapshot built by merging modified-window results into an existing snapshot equal the
> snapshot a full fetch would produce at the same instant?

**Nothing is implemented in T-016A.** Semantics first.

---

## 1. What the current ingester actually does

Read from `src/security_llm/data/ingest_nvd.py`, not from documentation.

| Aspect | Current behaviour |
|---|---|
| Endpoint | `services.nvd.nist.gov/rest/json/cves/2.0` |
| Partitioning | **`pubStartDate` / `pubEndDate`**, 119-day windows from `configs/data.yaml` |
| Window directory | `data/raw/nvd/<pub_start>_<pub_end>/page_<startIndex:07d>.json` |
| Pagination | `startIndex += body["resultsPerPage"]` until `startIndex >= body["totalResults"]` |
| Page cache | a page file that exists is reused unless `--force` |
| Writes | `atomic_write_json` per page |
| Retry | 403/429/5xx retried up to `max_retries` with `sleep * 2**attempt`; other statuses raise |
| Rate limiting | fixed sleep after every request, 6.5 s without a key and 0.7 s with one |
| Manifest | written **once, after every window finishes** |

### 1.1 What it does **not** guarantee

These are the gaps that matter, and the first is the most serious.

**`complete` is hardcoded.** The manifest entry is built as
`{"pub_start": …, "pub_end": …, "total_results": total, "pages": pages, "complete": True}` —
`True` is a literal, appended once the pagination loop exits. It is not a validation of
anything.

`normalize()` gates on exactly this field:

```python
for window in manifest["windows"]:
    if not window.get("complete"):
        continue
```

So **the completeness gate the whole pipeline relies on currently cannot fail.** Any
incremental design that leans on it is leaning on nothing. This must be replaced by a real
check before incremental ingest is trusted.

**No reconciliation of fetched rows against `totalResults`.** The loop never sums
`len(page["vulnerabilities"])` across pages and compares it to `totalResults`. A short page,
a silently truncated response or a mid-window pagination shift would not be detected.

**No checkpoint.** The manifest is written only after the final window. A crash leaves pages
on disk with no manifest, so `normalize()` cannot run at all — fail-safe, but it means resume
is implicit in page-file existence and carries no record of how far the run got, or under what
query parameters those pages were fetched.

**Cached pages are never revalidated.** `page_file.exists()` is the whole test. A page written
by an earlier run with different parameters, or during a window whose `totalResults` has since
changed, is reused without question.

**`totalResults` drift during pagination is undetected.** NVD data can change between page
requests; the loop reads `totalResults` fresh on each page but never compares it to the value
seen on page 0.

---

## 2. NVD API semantics

Separated into what the documentation states and what still has to be probed. **Nothing in the
second table may be assumed when writing code.**

### 2.1 Documented

| Item | Statement |
|---|---|
| Maximum date range | 120 consecutive days for any date-range parameter |
| Pairing | `lastModStartDate` and `lastModEndDate` are **both required** when filtering by last-modified date |
| Recommended incremental workflow | `lastModStartDate` = the time of the last record received, `lastModEndDate` = now, **no more than once every two hours** |
| Rejected records | returned by default; a separate parameter exists to exclude them |
| Current config alignment | `window_days: 119` already sits inside the 120-day limit |

### 2.2 A documented failure of exactly this mechanism

NVD has published an advisory telling `lastModStartDate` users to **reset their start date to
`2025-02-26T00:00:00.000`** because an internal issue with processing analyzed CVEs meant
updates were not being applied correctly in consumers' environments.

This is not hypothetical risk. It is a recorded instance of incremental sync silently missing
updates while appearing to succeed, in the exact mechanism this track is evaluating. Any design
here must assume the upstream change feed can be wrong and must be reconcilable against a full
fetch. **Periodic full reconciliation is a requirement, not an optimisation.**

### 2.3 Not established — must be probed before use

| Question | Status |
|---|---|
| Is `lastModStartDate` inclusive or exclusive? | **unknown** |
| Is `lastModEndDate` inclusive or exclusive? | **unknown** |
| Timestamp precision and timezone handling at the boundary | **unknown** |
| Can one CVE appear in two adjacent lastMod windows? | **unknown** |
| Are results ordered by modification time? | **unknown** — must not be assumed |
| Do newly published CVEs appear in a lastMod query? | **unknown** |
| Is `totalResults` stable across a window's pagination? | **unknown** |
| Is there any deletion signal at all? | **unknown** |

The official recommendation — start the next window at the timestamp of the last record
received — only makes sense under a particular inclusivity, and it produces either duplicates
or omissions under the other. Since we cannot tell which from the documentation, **§5 assumes
the unsafe direction and overlaps deliberately.**

---

## 3. The structural mismatch

**The raw cache is partitioned by published date; incremental fetch is keyed by last-modified
date.** These do not line up.

A CVE published in 2021 and modified in 2026 arrives from a modified-window fetch but belongs,
under the existing layout, in `data/raw/nvd/2021-…/`. Merging it means rewriting a page inside
an old published-date window, which breaks three things the current design depends on:

- the page file as an immutable cache keyed by `(window, startIndex)`;
- `totalResults`-based pagination, since a rewritten window no longer corresponds to any single
  API response;
- the ability to re-derive a window by refetching it.

There are two honest options, and T-016B measures rather than assumes:

- **Option A — overlay.** Keep published-date pages immutable and add a separate
  `data/raw/nvd/_updates/<lastmod_window>/` tree. `normalize()` reads base pages, then applies
  the overlay by `cve_id`, last write wins by `lastModified`. Snapshot identity becomes base
  plus ordered overlay windows. Nothing existing is rewritten.
- **Option B — repartition.** Move to a last-modified-partitioned cache. Cleaner for
  incremental, but it invalidates the existing 2.1 GB snapshot and every artifact derived from
  it, and T-014/T-015 baselines are frozen.

Option A is the only one compatible with the freeze, so it is the working assumption. It is
recorded as an assumption, not a conclusion.

---

## 4. Checkpoint model

A checkpoint is not a timestamp. It records a verified unit of work:

```
window_start, window_end          the lastMod range actually requested
fetch_started_at, fetch_completed_at
pages, rows_fetched, total_results_first_page, total_results_last_page
row_count_matches_total           bool — the real completeness check
page_hashes[]                     sha256 per persisted page
window_hash                       over the ordered page hashes
snapshot_identity_before/after
status                            COMPLETE | REJECTED | REVIEW_REQUIRED
```

The checkpoint advances **only** after every page is persisted, re-read and verified.
`row_count_matches_total` replaces the hardcoded `complete: True` of §1.1.

## 5. Window lifecycle

```
fetch → validate → persist → re-read and verify → mark complete → advance checkpoint
```

The checkpoint is never advanced before the fetch, and never on a partially persisted window.
A failure leaves the previous checkpoint intact and the run resumes from it.

**Boundary overlap is deliberate.** Because §2.3 leaves inclusivity unknown, each window starts
slightly before the previous window's end. Overlap costs a little duplicate fetching; a missed
boundary costs a silently incomplete dataset. That trade is not close.

Overlap requires, and these are mandatory: duplicate `cve_id` across windows is expected and
legal; merge is deterministic; and the resolution rule is explicit — highest `lastModified`
wins, ties broken by later window, and an exact-equal record is a no-op.

## 6. Merge rule

Identity is `cve_id`. A fetched record absent from the base snapshot is an `INSERT`; one
present is an `UPDATE` candidate.

**`lastModified` alone never decides that a record changed.** §1 of `docs/CHANGE_MODEL.md`
established that NVD moves `lastModified` for changes that do not touch the dataset. The
decision uses the canonical comparison in §7.

## 7. Canonical raw identity

Two hashes per record, for two different questions:

- **Canonical semantic hash** — over the record with object keys sorted recursively, NFC-normalized
  text, `null` and absent treated alike, and arrays whose order is not meaningful sorted by a
  declared key. Answers "did this record change?"
- **Raw byte hash** — over the bytes as received. Answers "is this the same response?" and is
  what page and window hashes are built from.

Array order needs a decision per field rather than a blanket rule: `descriptions` and
`weaknesses` have no documented ordering guarantee, so ordering differences alone must not be
reported as changes. Record which arrays were normalized and why.

## 8. Idempotency

Applying the same window twice must be a no-op:

```
Snapshot_A ⊕ W = Snapshot_B
Snapshot_B ⊕ W = Snapshot_B
```

Verified on: row duplication, ordering drift, manifest corruption, content-hash drift, and
checkpoint state. Both `⊕` results are compared by snapshot hash, not by row count.

## 9. Failure and retry

| Failure point | Artifact state | Checkpoint | Resume |
|---|---|---|---|
| page 1 ok, page 2 fails | page 1 persisted | not advanced | refetch window from page 0; overlap makes this safe |
| fails before window persisted | nothing persisted | not advanced | refetch window |
| persisted, fails before checkpoint | window persisted | not advanced | re-verify persisted window, then advance — **must be idempotent** |
| fails while writing checkpoint | window persisted | partially written | checkpoint write is atomic; a torn write is treated as not advanced |
| rate limit / timeout | none | not advanced | back off and retry the same window |
| invalid JSON | page rejected | not advanced | refetch; never persist unparseable content |
| short page / count mismatch | window **REJECTED** | not advanced | refetch whole window |

## 10. Incomplete windows

A window failing validation is **rejected**, not merged. The checkpoint does not advance and
the snapshot is not updated. Partial data never enters a snapshot quietly — that is the failure
mode §2.2 shows actually happens in the field.

## 11. MISSING

Unchanged from `docs/CHANGE_MODEL.md` §2: **`MISSING` is not `DELETE`.** A modified-window
fetch not returning a CVE is not a deletion signal — a record is only expected there if it was
modified in that range. Withdrawal appears as `vulnStatus` becoming `Rejected`, which is an
`UPDATE`. No API deletion signal is established (§2.3), so no row is ever removed by
incremental ingest.

## 12. Equivalence layers

T-015's three layers, with a source layer added. **S0 is T-016's primary success criterion.**

| | Layer | Compared |
|---|---|---|
| **S0** | Source snapshot | `cve_id` set symmetric difference; canonical semantic hash per record; dataset-relevant raw fields (`published`, `descriptions`, `vulnStatus`, `weaknesses`, `cisaExploitAdd`); total count |
| S1 | Composition | selected IDs, labels, splits, dedup survivors, SFT membership |
| S2 | Final byte | `data/sft/*.jsonl` and hashes |
| S3 | Intermediate byte | normalized and processed artifacts |

Count equality never passes S0 on its own. S1–S3 follow from a deterministic full rebuild on
each snapshot, which T-015 established is cheap.

## 13. T-016B controlled test plan

1. **Probe the unknowns in §2.3 first**, with the smallest queries that settle each one, and
   record request and response verbatim. Boundary inclusivity is the blocker; nothing else
   proceeds without it.
2. Build Snapshot A from a bounded published-date slice already cached, so the baseline is
   offline and reproducible.
3. Fetch the modified window covering the period since Snapshot A's basis.
4. Merge under §5–§7 to produce the incremental snapshot.
5. Fetch a **full snapshot at the same instant** as truth.
6. Compare on S0. Then rebuild both downstream and compare S1–S3.
7. Idempotency per §8.
8. Only after all of that: request count, rows fetched, wall time, retries, rate-limit events,
   artifact size, against the 2 to 2.5 hour full-ingest baseline.

Truth is always the full fetch. The merged snapshot is what is being judged.

## 14. Stop conditions

Stop, and keep full ingest, if change-fetch cannot be made reliable, if same-instant
equivalence cannot be demonstrated, if boundary omission risk cannot be closed, if
retry/checkpoint complexity outweighs the saving, or if real change volume is large enough that
incremental approaches full fetch anyway.

Given §2.2, one additional condition is non-negotiable: **if incremental ingest cannot be
reconciled against a periodic full fetch, it is not adopted.** Speed is never taken in exchange
for source completeness, and any possibility of silent omission stops the optimisation.

## 15. Not in this track

No production fetcher, scheduler, Kafka, Airflow, Spark Streaming, Delta Lake, Iceberg, Hudi,
Ray, database migration, deployment or cron orchestration. Semantics first.
