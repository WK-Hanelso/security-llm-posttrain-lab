"""Deterministic local Spark session construction."""

from __future__ import annotations

import os
import sys

# Set this before importing pyspark so the JVM never depends on host networking.
os.environ.setdefault("SPARK_LOCAL_IP", "127.0.0.1")
# A venv interpreter invoked by absolute path does not put its ``bin`` directory
# first on PATH.  Spark otherwise discovers the host ``python3`` for workers,
# which can have a different minor version from the driver.
os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

from pyspark.sql import SparkSession


def build_spark_session(
    master: str = "local[8]", shuffle_partitions: int = 64, app_name: str = "security-llm-track-a"
) -> SparkSession:
    """Build the single-node Spark session used by every Track A command."""

    spark = (
        SparkSession.builder.appName(app_name)
        .master(master)
        .config("spark.sql.shuffle.partitions", str(shuffle_partitions))
        .config("spark.sql.adaptive.enabled", "false")
        .config("spark.speculation", "false")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark
