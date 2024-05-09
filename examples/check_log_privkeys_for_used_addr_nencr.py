"""\
An example which searches a 'armory_wallet_checksum_searcher' log file for
unencrypted private keys which lead to used addresses.

To test this script, you can run the following from the repo root:

python examples/check_log_privkeys_for_used_addr_nencr.py tests/test_data/armory_wallet_checksum_searcher_demos/armory_wallet_checksum_searcher_demo_31hTA1aRV.wallet.log tests/test_data/armory_wallet_checksum_searcher_demos/fake_addr_list.txt  # noqa
python examples/check_log_privkeys_for_used_addr_nencr.py tests/test_data/armory_wallet_checksum_searcher_demos/armory_wallet_checksum_searcher_demo_QPriwP2F.wallet.log tests/test_data/armory_wallet_checksum_searcher_demos/fake_addr_list.txt  # noqa
"""

import argparse
from pathlib import Path

from loguru import logger
import polars as pl
from used_addr_check import search_multiple_in_file

from armory_lib.specific_parsing import read_checksum_log_into_df
from armory_lib.calcs import unencrypted_priv_key_to_address


def check_log_for_unencrypted_used_addr(
    input_log_file: str | Path,
    used_addr_file: str | Path,
):
    """Check a 'armory_wallet_checksum_searcher' log file for used addresses.

    The used_addr_file should be a file containing a list of used addresses,
    from loyce.club's "all bitcoin addresses ever used" list:
    http://alladdresses.loyce.club/all_Bitcoin_addresses_ever_used_sorted.txt.gz.
    """

    df = read_checksum_log_into_df(input_log_file)
    logger.info(f"Loaded {len(df):,} checksum passes from the log file.")

    if isinstance(used_addr_file, str):
        used_addr_file = Path(used_addr_file)

    df = df.filter(pl.col("chunk_length") == pl.lit(32))
    logger.info(
        f"Filtered to {len(df):,} checksum passes with 32-byte chunks."
    )
    priv_key_list = df["chunk_hex_str"].to_list()

    addr_to_priv_key = {}
    for priv_key in priv_key_list:
        addr1 = unencrypted_priv_key_to_address(bytes.fromhex(priv_key))
        addr_to_priv_key[addr1] = priv_key

        # TODO: could try reversing the bytes, and try with compressed=True,
        # but those are unlikely to be valuable for old Armory wallets

    logger.info(
        f"Found {len(addr_to_priv_key)} addresses in the JSON file. "
        f"Searching in {used_addr_file}..."
    )

    found_addr_list = search_multiple_in_file(
        used_addr_file,
        list(addr_to_priv_key.keys()),
    )

    if found_addr_list:
        for addr1 in found_addr_list:
            logger.info(f"Found used address: {addr1}")
            logger.info(f"Private key: {addr_to_priv_key[addr1]}")
        # TODO: show these as a dataframe table
    else:
        logger.info("No used addresses found.")


def main():
    parser = argparse.ArgumentParser(
        description="Check a 'armory_wallet_checksum_searcher' log file for used addresses."  # noqa
    )
    parser.add_argument(
        "input_log_file",
        type=str,
        help="The 'armory_wallet_checksum_searcher' log file to search.",
    )
    parser.add_argument(
        "used_addr_file",
        type=str,
        help="A file containing a list of used addresses.",
    )
    args = parser.parse_args()

    check_log_for_unencrypted_used_addr(
        args.input_log_file,
        args.used_addr_file,
    )


if __name__ == "__main__":
    main()
