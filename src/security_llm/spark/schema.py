"""Schemas shared by the Spark Track A stages and equivalence checks."""

from __future__ import annotations

from pyspark.sql.types import (
    ArrayType,
    BooleanType,
    DoubleType,
    StringType,
    StructField,
    StructType,
)

DESCRIPTION_SCHEMA = StructType(
    [StructField("lang", StringType()), StructField("value", StringType())]
)
WEAKNESS_SCHEMA = StructType(
    [
        StructField("type", StringType()),
        StructField("description", ArrayType(DESCRIPTION_SCHEMA)),
    ]
)
CVSS_DATA_SCHEMA = StructType(
    [
        StructField("baseScore", DoubleType()),
        StructField("baseSeverity", StringType()),
    ]
)
METRIC_SCHEMA = StructType([StructField("cvssData", CVSS_DATA_SCHEMA)])
CVE_SCHEMA = StructType(
    [
        StructField("id", StringType()),
        StructField("published", StringType()),
        StructField("lastModified", StringType()),
        StructField("vulnStatus", StringType()),
        StructField("descriptions", ArrayType(DESCRIPTION_SCHEMA)),
        StructField("weaknesses", ArrayType(WEAKNESS_SCHEMA)),
        StructField(
            "metrics",
            StructType([StructField("cvssMetricV31", ArrayType(METRIC_SCHEMA))]),
        ),
        StructField("cisaExploitAdd", StringType()),
    ]
)
RAW_PAGE_SCHEMA = StructType(
    [
        StructField(
            "vulnerabilities",
            ArrayType(StructType([StructField("cve", CVE_SCHEMA)])),
        )
    ]
)

NORMALIZED_SCHEMA = StructType(
    [
        StructField("cve_id", StringType(), False),
        StructField("published", StringType(), False),
        StructField("last_modified", StringType(), False),
        StructField("vuln_status", StringType(), False),
        StructField("description_en", StringType(), False),
        StructField("description_norm_hash", StringType(), False),
        StructField("cwe_primary", ArrayType(StringType(), False), False),
        StructField("cwe_secondary", ArrayType(StringType(), False), False),
        StructField("cwe_all", ArrayType(StringType(), False), False),
        StructField("placeholder_only", BooleanType(), False),
        StructField("cwe_id", StringType(), True),
        StructField("label_status", StringType(), False),
        StructField("cvss_v31_base_score", DoubleType(), True),
        StructField("cvss_v31_severity", StringType(), True),
        StructField("is_kev", BooleanType(), False),
        StructField("kev_date_added", StringType(), True),
        StructField("is_rejected", BooleanType(), False),
    ]
)

NORMALIZED_FIELDS = [field.name for field in NORMALIZED_SCHEMA.fields]


def split_schema() -> StructType:
    return StructType(list(NORMALIZED_SCHEMA.fields) + [StructField("split", StringType(), False)])
