# T-013 execution record

## Preconditions

I ran:

```text
git branch --show-current
git rev-parse HEAD
```

The results were `feat/distributed-pipeline` and
`73a8948c2680ced114f239657e340784b11a1f34`. The branch was not `main`, so work
continued. I did not install or use Ray or Spark, did not use the network, and
used `.venv/bin/python` throughout.

## Implementation

I added `src/security_llm/bench/near_duplicate_scaling.py` and its package
initializer. I did not modify anything under `src/security_llm/data`,
`src/security_llm/eval`, or `src/security_llm/train`.

The benchmark imports the seed, vectorizer class, and cosine implementation
from `security_llm.eval.near_duplicate_audit`. Before measuring, an AST check
confirms that the protected audit still uses the exact required vectorizer
arguments and `dense_output=True`. It runs each executable `(N, shape)` in a
fresh subprocess, with child `ru_maxrss` measurement and parent-side monitoring
of RSS, threads, swap, available memory, elapsed time, load, exit code, and
stderr.

The stop checks are executable code: 12 GiB projected/observed RSS, 30-minute
projected/observed wall time, any swap increase, any major fault, a 2 GiB
available-memory stability floor, child failure, and an information stop after
at least four points establish a quadratic similarity trend (accepted slope
1.6–2.4 and R² at least 0.95).

## Commands and runs

I compiled the new module and ran a ten-row child smoke check:

```text
.venv/bin/python -m py_compile \
  src/security_llm/bench/__init__.py \
  src/security_llm/bench/near_duplicate_scaling.py
.venv/bin/python -m security_llm.bench.near_duplicate_scaling \
  --child --shape internal_all_pairs --n 10 \
  --train data/sft/train.jsonl --test data/sft/test.jsonl
```

I then ran the parent benchmark:

```text
.venv/bin/python -m security_llm.bench.near_duplicate_scaling \
  --output reports/distributed/gate1_scaling.json
```

The first cold invocation completed only `query_vs_reference, N=300` and then
correctly stopped the remaining ladder after the child reported two major
faults. Swap did not change. I preserved that result during diagnosis at
`/tmp/t013-first-aborted.json`; it is a disposable diagnostic, not a repository
artifact. Because the faults were isolated to the first cold execution rather
than accompanied by paging pressure, I started a new parent invocation against
the warmed local files/libraries. I did not relax the gate. The clean invocation
recorded zero major faults and zero swap growth at every completed point.

The clean invocation executed these fresh children:

- `query_vs_reference`: `Q=300, 1,000, 2,500, 5,000, 10,000, 24,975`, always
  against `R=12,000`.
- `internal_all_pairs`: `N=300, 1,000, 2,500, 5,000`.

It refused `internal_all_pairs` at `N=10,000` and again at `N=24,975`. After
four points, similarity time had log-log slope 1.870 with R² 0.9995. This met
the implemented “quadratic trend already established; next point adds no new
decision information” condition. Neither refusal was an OOM or failed run.

## Results

| Shape | N/Q | R | Pairs or scores | Total s | Vectorizer s | Similarity s | Reduction s | Peak RSS GiB | Outcome |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|:---|
| query_vs_reference | 300 | 12,000 | 3,600,000 | 1.479 | 0.987 | 0.093 | 0.002 | 0.286 | completed |
| query_vs_reference | 1,000 | 12,000 | 12,000,000 | 1.749 | 1.074 | 0.273 | 0.006 | 0.352 | completed |
| query_vs_reference | 2,500 | 12,000 | 30,000,000 | 2.266 | 1.212 | 0.648 | 0.015 | 0.494 | completed |
| query_vs_reference | 5,000 | 12,000 | 60,000,000 | 3.291 | 1.525 | 1.338 | 0.030 | 0.730 | completed |
| query_vs_reference | 10,000 | 12,000 | 120,000,000 | 6.252 | 1.985 | 3.809 | 0.060 | 1.200 | completed |
| query_vs_reference | 24,975 | 12,000 | 299,700,000 | 15.163 | 3.555 | 11.018 | 0.175 | 2.619 | completed |
| internal_all_pairs | 300 | — | 44,850 | 0.321 | 0.041 | 0.003 | <0.001 | 0.193 | completed |
| internal_all_pairs | 1,000 | — | 499,500 | 0.449 | 0.144 | 0.029 | 0.001 | 0.206 | completed |
| internal_all_pairs | 2,500 | — | 3,123,750 | 0.732 | 0.290 | 0.168 | 0.003 | 0.254 | completed |
| internal_all_pairs | 5,000 | — | 12,497,500 | 1.510 | 0.568 | 0.658 | 0.012 | 0.407 | completed |
| internal_all_pairs | 10,000 | — | 49,995,000 | — | — | — | — | — | stopped before launch: trend complete |
| internal_all_pairs | 24,975 | — | 311,862,825 | — | — | — | — | — | stopped before launch: trend complete |

For the fixed-reference shape, the similarity slope was 1.086 (R² 0.9908), and
the final 2.498× query-size increase produced 2.425× total wall growth. This is
consistent with linear scaling on `Q`; the full test query population completed.

For internal all-pairs, doubling `N` from 2,500 to 5,000 increased unique pairs
4.001× and similarity time 3.915× (0.168 s to 0.658 s). Total time grew only
2.063× because fixed input loading and linear vectorization still represented
55.4% of wall time at `N=5,000`. The similarity kernel itself is the measured
quadratic component.

## Conclusion and next track

The experiment stopped with the largest completed internal point at `N=5,000`;
the next point was rejected because the quadratic decision was already clear,
not because a process failed. **Case A holds.** Case C was not observed. The
existing query-versus-reference form completed `24,975 × 12,000` on this host,
but that linear result must not be conflated with the quadratic internal audit.

Recommendation: end this dense exact all-pairs track and measure candidate
reduction next—blockwise exact top-k, LSH, ANN, or candidate generation plus
exact cosine refinement—with bounded memory and recall checked against these
exact small-N results.

## Verification

- `py_compile` passed for both new package files.
- Machine-readable artifact assertions passed: 12 ladder records, the expected
  completed/stopped sizes, the requested implementation commit on every record,
  zero clean-run major faults, and zero clean-run swap growth.
- The non-Spark test suite passed: **35 passed, 1 skipped**.
- An unfiltered `pytest -q` could not collect three pre-existing Spark test
  modules because `pyspark` is not installed. I did not install it or run Spark.
- `git diff --check` passed, the protected source directories were unchanged,
  and the prohibited-claim wording scan was empty.
- `agent/` is locally ignored by `.git/info/exclude`; consequently
  `agent/T-013_EXEC.md` exists as required but the orchestrator will need to add
  it explicitly when committing.
