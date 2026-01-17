from pathlib import Path

import polars as pl

from armory_lib.specific_parsing import read_checksum_log_into_df

TEST_ROOT_PATH = Path(__file__).parent.parent


def test_read_checksum_log_into_df():
    df = read_checksum_log_into_df(
        TEST_ROOT_PATH
        / "test_data"
        / "armory_wallet_checksum_searcher_demos"
        / "QPriwP2F_short.wallet.log"
    )

    assert isinstance(df, pl.DataFrame)
    assert len(df) == 1
    assert df.shape == (1, 7)

    row = df.to_dicts()[0]
    assert row["file_path"] == ["./armory_QPriwP2F_encrypt.wallet"]
    assert row["hash_hex_str"] == "ab8692d7"
    assert (
        row["chunk_hex_str"]
        == "0000000400000000010000006fd1ec64860efe905a028f7fdcc70ca3804cf0832360bd582425c0988b3d71be"  # noqa
    )
    assert row["offset"] == 334
    assert row["chunk_length"] == 44
    assert row["hash_bytes"] == b"\xab\x86\x92\xd7"
    assert row["chunk_bytes"] == bytes.fromhex(row["chunk_hex_str"])

    assert len(row["hash_bytes"]) == 4
    assert len(row["chunk_bytes"]) == row["chunk_length"]
