from pathlib import Path

import polars as pl
from loguru import logger

from armory_lib.parsing import normalize_csv_hex_str


def read_checksum_log_into_df(file_path: Path) -> pl.DataFrame:
    with open(file_path, "r") as fp:
        lines = fp.readlines()

    lines = [line for line in lines if "Hash: [" in line]

    df = pl.DataFrame([{"full_line": line} for line in lines])
    df = df.select(
        hash_hex_str_csv=pl.col("full_line").str.extract(
            r"Hash: \[([\w ,]+)\]"
        ),
        chunk_hex_str_csv=pl.col("full_line").str.extract(
            r"Chunk: \[([\w ,]+)\]"
        ),
        offset=pl.col("full_line")
        .str.extract(r"Offset in File: (\d+)")
        .cast(pl.UInt64),
        chunk_length=pl.col("full_line")
        .str.extract(r"Chunk Length: (\d+)")
        .cast(pl.UInt8),
    ).with_columns(
        hash_hex_str=pl.col("hash_hex_str_csv").map_elements(
            normalize_csv_hex_str, return_dtype=pl.String
        ),
        chunk_hex_str=pl.col("chunk_hex_str_csv").map_elements(
            normalize_csv_hex_str, return_dtype=pl.String
        ),
    )
    df = (
        df.group_by(
            ["hash_hex_str", "chunk_hex_str", "offset", "chunk_length"]
        )
        .agg(occurrence_count=pl.len())
        .sort("occurrence_count")
    )

    df_duplicate_offsets = df.filter(
        pl.col("offset").is_unique() == pl.lit(False)
    )
    if len(df_duplicate_offsets) > 0:
        logger.warning(
            f"Found duplicate offsets in {file_path}: {df_duplicate_offsets}"
        )

    df = df.with_columns(
        hash_bytes=pl.col("hash_hex_str").str.decode("hex"),
        chunk_bytes=pl.col("chunk_hex_str").str.decode("hex"),
    )
    return df
