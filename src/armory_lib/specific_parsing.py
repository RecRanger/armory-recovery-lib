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
            offset=(
                pl.col("full_line")
                .str.extract(r"Offset in File: (\d+)")
                .cast(pl.UInt64)
            ),
            chunk_length=(
                pl.col("full_line")
                .str.extract(r"Chunk Length: (\d+)")
                .cast(pl.UInt8)
            ),
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

    # remove duplicates with the same 'offset'
    df = df.group_by(
        ["hash_hex_str", "chunk_hex_str", "offset", "chunk_length"]
    ).agg(
        file_path=pl.col("file_path").unique(),
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
        "file_path",
        "hash_bytes",
        "chunk_bytes",
    }
    return df


def log_checksum_summary(df_log: pl.DataFrame) -> None:
    """Logs a summary of the checksum DataFrame.

    Args:
        df: Result of read_checksum_log_into_df(...)
    """
    logger.info(f"Checksum summary: {df_log}")

    df_group_1 = (
        df_log.group_by("chunk_length")
        .agg(
            occurrence_count=pl.len(),  # at distinct offsets
            distinct_finds=pl.col("chunk_hex_str").n_unique(),
        )
        .sort("chunk_length")
    )
    logger.info(f"Checksum summary by chunk length: {df_group_1}")

    # find the most-occurring ones
    df_group_2 = (
        df_log.group_by(["chunk_hex_str", "hash_hex_str", "chunk_length"])
        .agg(
            occurrence_count=pl.len(),
            min_offset=pl.col("offset").min(),
            max_offset=pl.col("offset").max(),
            offset_list=pl.col("offset").unique().sort(),
        )
        .sort("occurrence_count", descending=True)
        .head(10)
    )
    logger.info(f"Top most-occurring checksums: {df_group_2}")


def log_checksum_len20_facts(df_log: pl.DataFrame) -> None:
    from armory_lib.calcs import address_hash160_to_address

    # find the most-occurring chunk_length=20 ones, and show their addresses
    df_most_found = (
        df_log.group_by(["chunk_hex_str", "hash_hex_str", "chunk_length"])
        .agg(
            occurrence_count=pl.len(),
            min_offset=pl.col("offset").min(),
            max_offset=pl.col("offset").max(),
            offset_list=pl.col("offset").unique().sort(),
        )
        .sort(["occurrence_count", "min_offset"], descending=[True, False])
    )
    df_most_found_addr = (
        df_most_found.filter(pl.col("chunk_length") == pl.lit(20))
        .head(30)
        .with_columns(
            address=pl.col("chunk_hex_str").map_elements(
                lambda x: address_hash160_to_address(bytes.fromhex(x)),
                return_dtype=pl.String,
            )
        )
    )
    logger.info(
        f"Top most-occurring checksums (with addresses): {df_most_found_addr}"
    )
    df_most_used_json = df_most_found_addr.select(
        ["occurrence_count", "address", "offset_list"]
    ).write_ndjson()
    logger.info(
        f"Top most-occurring checksums (with addresses):\n{df_most_used_json}"
    )


def log_checksum_len44_facts(df_log: pl.DataFrame) -> None:
    from armory_lib.types.py_btc_kdf_params import PyBtcKdfParamsMinimal

    df_most_found = (
        df_log.group_by(["chunk_hex_str", "hash_hex_str", "chunk_length"])
        .agg(
            occurrence_count=pl.len(),
            min_offset=pl.col("offset").min(),
            max_offset=pl.col("offset").max(),
            offset_list=pl.col("offset").unique().sort(),
        )
        .sort(["occurrence_count", "min_offset"], descending=[True, False])
    )

    # find the length=44 ones, and see how many could be valid KDF params
    df_explore_kdf = (
        df_most_found.filter(pl.col("chunk_length") == pl.lit(44))
        .with_columns(
            kdf_mem_requirement=pl.col("chunk_hex_str").map_elements(
                lambda x: PyBtcKdfParamsMinimal.from_bytes(
                    bytes.fromhex(x)
                ).memory_requirement,
                return_dtype=pl.UInt64,  # UInt64 is important here!
            ),
            kdf_num_iterations=pl.col("chunk_hex_str").map_elements(
                lambda x: PyBtcKdfParamsMinimal.from_bytes(
                    bytes.fromhex(x)
                ).num_iterations,
                return_dtype=pl.Int64,
            ),
        )
        .with_columns(
            kdf_mem_MiB=pl.col("kdf_mem_requirement") / pl.lit(1024 * 1024),
            kdf_mem_GiB=(
                pl.col("kdf_mem_requirement") / pl.lit(1024 * 1024 * 1024)
            ),
            # add measures of feasibility for the KDF params
            is_good_mem=(
                pl.col("kdf_mem_requirement") % pl.lit(1024) == pl.lit(0)
            ),
            is_good_iter=(pl.col("kdf_num_iterations") <= pl.lit(5000)),
        )
        .sort(
            ["kdf_mem_requirement", "kdf_num_iterations"],
        )
    )
    df_kdf_null_mem = df_explore_kdf.filter(
        pl.col("kdf_mem_requirement").is_null()
    )
    if len(df_kdf_null_mem) > 0:
        logger.warning(
            f"Found KDF params with null memory requirement: {df_kdf_null_mem}"
        )

    with pl.Config(tbl_cols=100):
        logger.info(f"Found KDF params: {df_explore_kdf.head(10)}")

    df_explore_kdf_good_counts = (
        df_explore_kdf.group_by(["is_good_mem", "is_good_iter"])
        .agg(
            count=pl.len(),
            chunk_hex_str_list=pl.col("chunk_hex_str").unique().sort(),
        )
        .sort(["is_good_mem", "is_good_iter"])
    )
    logger.info(f"KDF params feasibility counts: {df_explore_kdf_good_counts}")

    df_explore_kdf_good = df_explore_kdf.filter(
        pl.col("is_good_mem") & pl.col("is_good_iter")
    )
    logger.info(f"Feasible KDF params:\n{df_explore_kdf_good.write_ndjson()}")


if __name__ == "__main__":
    df = read_checksum_log_into_df(
        Path(__file__).parent.parent.parent
        / "tests"
        / "test_data"
        / "armory_wallet_checksum_searcher_demos"
        / "QPriwP2F_short.wallet.log"
    )
    print(df)
