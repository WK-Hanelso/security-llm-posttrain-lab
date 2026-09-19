from security_llm.spark.session import build_spark_session
from security_llm.spark.split import select_labels_from_df, split_column


SPLITS = {
    "train": ["2020-01-01", "2024-12-31"],
    "val": ["2025-01-01", "2025-12-31"],
    "test": ["2026-01-01", None],
}


def test_temporal_boundaries_are_inclusive_and_label_ties_use_cwe_id(monkeypatch):
    monkeypatch.setenv("SPARK_LOCAL_IP", "127.0.0.1")
    spark = build_spark_session("local[1]", app_name="test-spark-split")
    try:
        dates = spark.createDataFrame(
            [("2020-01-01",), ("2024-12-31",), ("2025-01-01",), ("2025-12-31",),
             ("2026-01-01",), ("2026-09-17",), ("2026-09-18",)],
            ["published"],
        ).withColumn("split", split_column(SPLITS, "2026-09-17"))
        assert [row["split"] for row in dates.collect()] == [
            "train", "train", "val", "val", "test", "test", None
        ]

        labels = spark.createDataFrame(
            [("CWE-89",), ("CWE-89",), ("CWE-79",), ("CWE-79",), ("CWE-20",)],
            ["cwe_id"],
        )
        selected, counts = select_labels_from_df(labels, top_k=3, min_count=1)
        assert selected == ["CWE-79", "CWE-89", "CWE-20"]
        assert counts == {"CWE-79": 2, "CWE-89": 2, "CWE-20": 1}
    finally:
        spark.stop()
