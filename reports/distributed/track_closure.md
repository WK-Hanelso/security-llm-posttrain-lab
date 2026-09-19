# T-014 track closure

The track is closed. It moved from the repository's single-process data pipeline to a Spark local-mode reimplementation of normalization, temporal splitting, exact deduplication, and overlap checks. Spark reproduced the reference populations and row semantics; its purpose was equivalence, not a speed claim.

The proposed Ray work was then reviewed as a gated decision rather than an assumed implementation. The review separated two shapes that had previously been easy to conflate: internal N×N comparison, whose unique-pair count grows quadratically, and query-versus-reference Q×R comparison, which is linear in Q when R is fixed.

Gate 1 measured both. The internal exact similarity phase reproduced the quadratic finding through N=5,000, while the fixed-reference Q×R path completed Q=24,975 × R=12,000 in 15.163 seconds at 2.619 GiB. That distinction redirected the work from framework choice to the actual audit shape and memory behavior.

Audit A then established exact truth for the frozen 18,000 evaluation queries against 12,000 SFT references under a reference-only TF-IDF fit. The raw-float64 ordering was frozen as score descending and reference CVE ID ascending for bit-identical ties. The freeze also documented the cross-code-path one-ULP limitation instead of hiding it through score rounding.

Blockwise exact evaluation retained top-k and threshold pairs without holding the full dense matrix. Four block sizes reproduced Audit A truth, and 2,048 was fastest. The Audit B cost probe then measured nested Q=300, 1,000, and 2,500 subsets against all 65,272 references, with zero swap growth and zero major faults, and judged exact comparison sufficient for this scale.

This final run closed the projection with a measurement: 1,630,168,200 exact pairs completed in 96.639 seconds at 1.411 GiB peak RSS, block size 2,048, with 0 bytes of swap growth and 0 major faults. The full-split analysis and independent random-subset check are recorded beside the retained Parquet artifact.

LSH, ANN, and Ray were not built because measurement did not show they were needed. That is the result of the track, not a shortfall. No new embedding model, similarity metric, or threshold tuning was introduced, and the dataset split and earlier result artifacts were left unchanged.

Measured runtime, projected runtime, and theoretical complexity remain separate statements. This is a single-node result for the fixed Audit B workload. Any later question raised by the observed structure is a separate decision and is not pursued here.
