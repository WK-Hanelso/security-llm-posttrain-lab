# Ray Track B decision plan

This is a decision plan, not a commitment to use Ray. The current audit is a sampled,
word-TF-IDF template-reuse check, not a formal semantic-overlap detector. No baseline in this
plan has been run, and no Ray result is claimed.

## 1. Candidate input scales

The current audit fits TF-IDF on 12,000 sampled training descriptions plus 300 sampled test
descriptions, then materializes a dense `300 × 12,000` cosine matrix. That is 3,600,000
query/reference scores. A population-wide audit is a different shape: comparing every record
with every other record has `n(n−1)/2` unique unordered pairs.

| Population | Rows | Unique within-population pairs | Scores against the current 12,000-row reference |
|---|---:|---:|---:|
| Current sampled audit | 300 | 44,850 | 3,600,000 |
| Test split | 24,975 | 311,862,825 | 299,700,000 |
| Train population | 65,272 | 2,130,184,356 | 783,264,000 |
| All single-label records | 194,797 | 18,972,838,206 | 2,337,564,000 |
| Full normalized population | 257,913 | 33,259,428,828 | 3,094,956,000 |

The final column is the faithful scale-up of today's query-against-training-reference shape.
The pair column is the cost of an internal audit of each named population. The latter is the
research target implied by “full-population,” and its quadratic growth is the central limit.
At float64, only the upper-triangle scores for the full population would occupy about 266 GB;
a square dense matrix would occupy about 532 GB before sparse TF-IDF storage and working
memory. The 194,797 single-label and 257,913 normalized populations are useful scale probes,
but they are not automatically valid train/test contamination populations.

## 2. Baseline execution path

First preserve the existing 300-row execution exactly and write only disposable measurement
artifacts. From the repository root, the reference command is:

```bash
mkdir -p /tmp/ray-track-b-baseline/sample-300
/usr/bin/time -v \
  -o /tmp/ray-track-b-baseline/sample-300/time.txt \
  .venv/bin/python -m security_llm.eval.near_duplicate_audit \
  --train data/sft/train.jsonl \
  --test data/sft/test.jsonl \
  --base experiments/exp_001_baseline/predictions.jsonl \
  --sft experiments/exp_002_sft_v1/predictions.jsonl \
  --manifest reports/eval_subset_manifest.json \
  --json-output /tmp/ray-track-b-baseline/sample-300/result.json \
  --markdown-output /tmp/ray-track-b-baseline/sample-300/result.md
```

Before measuring larger inputs, add a measurement-only wrapper around the existing
`TfidfVectorizer` and `cosine_similarity` path. That wrapper is future work and is not part of
this plan deliverable. It must accept a query JSONL, a reference JSONL, a deterministic row
limit, seed 42, and an output directory; it must not add batching, multiprocessing, ANN, or
Ray, because any of those would change the baseline being measured. It should normalize the
input schemas to `cve_id`, `cwe_id`, and `description` and record input SHA-256 values,
scikit-learn/NumPy versions, row order, vocabulary size, matrix shapes, and output hashes.

Run one fresh process per query size against the unchanged 12,000-row
`data/sft/train.jsonl` reference. Use deterministic CVE-ID ordering and sizes 300, 1,000,
5,000, 10,000, and 24,975 for `data/processed/test.jsonl`. The larger populations are scale
probes, not contamination results:

```bash
for spec in \
  test:data/processed/test.jsonl:24975 \
  train:data/processed/train.jsonl:65272 \
  single:data/processed/normalized.jsonl:194797 \
  full:data/processed/normalized.jsonl:257913
do
  name=${spec%%:*}
  rest=${spec#*:}
  input=${rest%:*}
  limit=${spec##*:}
  out=/tmp/ray-track-b-baseline/${name}-${limit}
  mkdir -p "$out"
  /usr/bin/time -v -o "$out/time.txt" \
    .venv/bin/python scripts/benchmark_near_duplicate_baseline.py \
    --query "$input" \
    --reference data/sft/train.jsonl \
    --limit "$limit" \
    --seed 42 \
    --output "$out/result.json"
done
```

For `single`, the wrapper must filter `label_status == "single"` before applying the limit;
`full` applies no label filter. Record a preflight memory estimate before every run. If the
projected dense matrix alone exceeds 50% of currently available RAM, do not launch it; record
the run as rejected by the memory gate. A rejected or killed run is a baseline outcome, not a
reason to silently substitute a blocked or approximate algorithm. Because the current
vectorizer is fitted on reference plus query text, each scale has different IDF weights and
is its own reference result; similarity values across scales are not directly comparable.

After the query/reference sweep, use the same wrapper in all-pairs mode only for scales that
pass the memory gate. Self-pairs must be excluded and each unordered pair counted once. Write
all measurement output under `/tmp/ray-track-b-baseline/`; do not overwrite the checked-in
near-duplicate reports.

## 3. Metrics to record

For each fresh-process run, record:

- Wall-clock time from `/usr/bin/time -v`, plus user and system CPU time.
- Maximum resident set size and whether swap, the OOM killer, allocation failure, or sustained
  paging occurred. “Did not complete” is a result and must retain the exit code and stderr.
- Average CPU utilization from `time` and one-second per-process CPU, RSS, and I/O samples
  from `pidstat -urd`; retain the raw samples rather than only an average.
- Input bytes; sparse TF-IDF shape, nonzero count, and data/index bytes; dense similarity
  matrix shape and projected/observed bytes; result JSON size; and total output-directory size
  from `du -B1`.
- Stage times for input parsing, vectorizer fit, query/reference transform, cosine comparison,
  top-neighbor reduction, and serialization.
- Completion status, exit code, first failing allocation or exception, and the largest scale
  that completed without swap or memory-pressure throttling.

Run the 300-, 1,000-, and 5,000-query cases three times and report the median, keeping every
raw record. Run larger cases once unless they complete within ten minutes and remain below
70% of available RAM; only then repeat them. Do not report projected timing as measured
timing.

## 4. Expected bottleneck candidates

These are hypotheses to test, not results.

| Scale | Expected first binding constraint | Reason |
|---|---|---|
| 300 queries against 12,000 train rows | Vectorizer setup and CPU compute | The 3.6 million-score dense matrix is about 29 MB, so orchestration and fitting are likely more visible than memory. |
| 24,975 test queries against 12,000 train rows | Memory pressure, then cosine CPU | The dense score matrix alone is about 2.40 GB; temporary arrays and sparse features increase peak RSS. |
| 65,272 rows, internal all-pairs | Memory before scheduling | A square float64 matrix is about 34.1 GB and represents 2.13 billion unique pairs. |
| 194,797 single-label rows, internal all-pairs | Pairwise explosion | A square matrix is about 303.6 GB; exact dense comparison is unlikely to reach a useful scheduling experiment on this host. |
| 257,913 rows, internal all-pairs | Pairwise explosion | A square matrix is about 532.2 GB and contains 33.26 billion unique pairs. |

Input JSONL is hundreds of megabytes rather than hundreds of gigabytes, so sequential input
I/O is not expected to bind first. That must still be measured. Serialization becomes a Ray
concern if workers repeatedly receive the TF-IDF reference matrix; an actor design would need
to keep a reference shard resident. Single-process scheduling is a plausible constraint only
after dense materialization is removed or bounded. Distributing the present dense all-pairs
operation would divide work but would not remove the quadratic total.

## 5. Conditions for and against Ray

Ray is a candidate only after the measurement identifies independently schedulable,
compute-bound batches. Use it only if all of these conditions hold:

- Candidate generation has already bounded comparisons with LSH or ANN, or exact comparison
  is blockwise with top-k reduction so no full dense matrix is retained.
- The largest scientifically relevant run takes at least 30 minutes on one process, spends at
  least 80% of wall time in CPU or model compute, and has less than 10% I/O wait.
- Each task has at least 30 seconds of useful compute, serialized inputs are below 10% of task
  time, and the reference data or model can remain resident in actors.
- A two-worker trial on the same fixed input is at least 1.5x faster end to end after Ray
  startup, while passing the equivalence checks in §6. More workers must improve throughput
  without raising peak aggregate memory beyond the host or cluster limit.
- The intended execution environment has multiple nodes or accelerators that the
  single-process implementation cannot use directly.

Ray is not the answer if the exact pair count or dense similarity matrix causes failure; that
is an algorithmic-complexity problem, and LSH or ANN is the next experiment. It is also not
the answer when the relevant run completes in under ten minutes below 70% memory, when tasks
are shorter than ten seconds, when CPU utilization is below 50% because input or paging is
binding, or when serialization exceeds 20% of task time. For a 300-row sample, Ray startup
and object-store overhead are expected to exceed any scheduling gain.

The current recommendation is therefore not to use Ray for the existing TF-IDF audit at any
scale reachable in this repository. Measure through the 24,975-row test population if the
memory gate permits it. At 65,272 rows and above, first replace exhaustive dense comparison
with a validated LSH/ANN candidate stage or blockwise top-k method. Reconsider Ray only if
that revised workload still crosses the 30-minute compute-bound threshold and has multiple
workers or accelerators available.

## 6. Equivalence verification design

For the unchanged TF-IDF path, the reference is the single-process output produced from the
same ordered input, exact vectorizer settings, seed, and pinned scikit-learn/NumPy versions.
The comparison key is `query_cve_id`. For each key, compare the selected
`nearest_reference_cve_id`, same-label flag, and cosine score. Require identical IDs and flags
and absolute score error at most `1e-10`. Resolve scores tied within `1e-10` by ascending
reference CVE ID so partition completion order cannot change the winner. Compare every query
for every scale whose exact baseline completes, not only a sample. Also require identical
counts at the 0.80 and 0.90 thresholds and identical input/output row sets.

For an embedding implementation, pin the model and tokenizer revisions, pooling and
normalization rules, maximum length, dtype, device type, batch size, input order, and seed.
Require one embedding per expected CVE ID and no duplicate or missing IDs. On the same device
class, compare float32 embeddings and cosine scores with absolute tolerance `1e-5`; for fp16
use `1e-3`. Exact bytes and cross-device equality are not valid requirements because GPU
kernels, batching, and floating-point reductions can differ.

Embedding similarity also does not mean semantic equivalence to the TF-IDF report: it changes
the metric and may change every nearest neighbor. Treat it as a new audit with a new reference,
not as a distributed reproduction of the checked-in audit. For an ANN index, verify a fixed,
class-stratified, seed-42 sample of at least 2,000 queries against exact brute-force neighbors
computed from the same frozen embeddings. Require recall@10 of at least 0.99, top-1 agreement
of at least 0.98, and report precision and recall for pairs crossing each audit threshold.
Apply schema, row-set, and duplicate checks to the full population, but do not claim full
nearest-neighbor equivalence unless an exact full-population comparison was actually run.

## 7. Sandbox and execution constraints

Static pair-count calculation, input validation, hashing, the existing scikit-learn audit,
the non-Ray baseline wrapper, and comparison of already-produced artifacts can run in the
default sandbox. They require no network service and should write measurement artifacts to
`/tmp`.

Installing Ray, downloading an uncached embedding model, or accessing remote object storage
would require permissions outside the default sandbox and is not part of this plan. Starting
a Ray head process, calling `ray.init()` when it starts local services, opening the dashboard,
and launching Ray workers bind loopback ports. Those steps are expected to encounter the same
loopback restriction recorded as B5 for Spark and need an execution environment that permits
local port binding. A failure at Ray initialization or worker registration under that
restriction is a sandbox result, not evidence of a Ray-code defect. Only failures reproduced
in a permitted environment should enter code diagnosis.

No Spark or Ray process is needed to carry out the preflight calculations, review this plan,
or decide that the pairwise algorithm must change first.
