from pathlib import Path

import polars as pl
from loguru import logger

from armory_lib.parsing import normalize_csv_hex_str


def read_checksum_log_into_df(log_file_path: str | Path) -> pl.DataFrame:
    """Reads a checksum log file into a DataFrame.
    The log can be a concatenation of multiple logs/executions.

    Reads the log from the accompanying project:
        https://github.com/recranger/armory-wallet-checksum-searcher
    """
    with open(log_file_path, "r") as fp:
        lines = fp.readlines()

    df = pl.DataFrame({"full_line": list(lines)})
    df = (
        df.select(
            pl.col("full_line"),
            file_path=pl.col("full_line").str.extract(
                r"Starting processing of file: .(.+)."
            ),
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
        )
        .with_columns(pl.col("file_path").fill_null(strategy="forward"))
        .filter(
            pl.col("full_line").str.contains("Hash: [", literal=True)
            & pl.col("chunk_hex_str_csv").is_not_null()
        )
        .with_columns(
            hash_hex_str=pl.col("hash_hex_str_csv").map_elements(
                normalize_csv_hex_str, return_dtype=pl.String
            ),
            chunk_hex_str=pl.col("chunk_hex_str_csv").map_elements(
                normalize_csv_hex_str, return_dtype=pl.String
            ),
        )
    )
    df = (
        df.group_by(
            ["hash_hex_str", "chunk_hex_str", "offset", "chunk_length"]
        )
        .agg(
            occurrence_count=pl.len(),
            file_path=pl.col("file_path").unique(),
        )
        .sort("occurrence_count")
    )

    df_duplicate_offsets = df.filter(
        pl.col("offset").is_unique() == pl.lit(False)
    )
    if len(df_duplicate_offsets) > 0:
        logger.warning(
            f"Found duplicate offsets in {log_file_path}: "
            f"{df_duplicate_offsets}"
        )

    df = df.with_columns(
        hash_bytes=pl.col("hash_hex_str").str.decode("hex"),
        chunk_bytes=pl.col("chunk_hex_str").str.decode("hex"),
    )

    assert set(df.columns) == {
        "hash_hex_str",
        "chunk_hex_str",
        "offset",
        "chunk_length",
        "occurrence_count",
        "file_path",
        "hash_bytes",
        "chunk_bytes",
    }
    return df


if __name__ == "__main__":
    df = read_checksum_log_into_df(
        Path(__file__).parent.parent.parent
        / "tests"
        / "test_data"
        / "armory_wallet_checksum_searcher_demos"
        / "QPriwP2F_short.wallet.log"
    )
    print(df)
