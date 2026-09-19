from security_llm.spark.dedup import keep_first_train
from security_llm.spark.session import build_spark_session


def test_keep_first_uses_published_then_cve_id(monkeypatch):
    monkeypatch.setenv("SPARK_LOCAL_IP", "127.0.0.1")
    spark = build_spark_session("local[1]", app_name="test-spark-dedup")
    try:
        # The later row is intentionally first in input; input order must not choose the survivor.
        rows = [
            ("CVE-2024-9999", "2024-02-01", "same", "train"),
            ("CVE-2024-0002", "2024-01-01", "same", "train"),
            ("CVE-2024-0001", "2024-01-01", "same", "train"),
            ("CVE-2024-0003", "2024-03-01", "different", "train"),
        ]
        frame = spark.createDataFrame(rows, ["cve_id", "published", "description_norm_hash", "split"])
        kept = {row["cve_id"] for row in keep_first_train(frame).collect()}
        assert kept == {"CVE-2024-0001", "CVE-2024-0003"}
    finally:
        spark.stop()
