from pathlib import Path

import polars as pl
from loguru import logger


def main():
    input_file_path = (
        TEST_ROOT_PATH / "all_Bitcoin_addresses_ever_used_sorted.txt"
    )
    output_file_path = TEST_ROOT_PATH / "all_btc_addr_startswith_1.parquet"
    logger.info(f"Input file path: {input_file_path}")
    logger.info(f"Output file path: {output_file_path}")

    df = pl.scan_csv(
        input_file_path, has_header=False, schema={"address": pl.String}
    )
    df = df.set_sorted("address")
    df = df.filter(pl.col("address").str.starts_with("1"))
    df.sink_parquet(output_file_path)

    logger.info(
        "Done writing."
        f"Output file size: {output_file_path.stat().st_size} bytes"
    )

    logger.info("Going to try reading it...")
    df = pl.scan_parquet(output_file_path)
    row_count = df.select(pl.len()).collect().item()
    logger.info(f"Number of rows: {row_count:,}")

    logger.info("Done.")


if __name__ == "__main__":
    main()
