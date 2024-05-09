"""\
An example which searches a JSON file with a list of unencrypted private keys
for used addresses.
"""

import argparse
import json
from pathlib import Path

from loguru import logger
from used_addr_check import search_multiple_in_file

from armory_lib.calcs import unencrypted_priv_key_to_address


def check_json_priv_keys_for_used_addr(
    input_json_file: str | Path,
    used_addr_file: str | Path,
):
    """Check a JSON file of private keys for used addresses.
    The JSON file should be a list of hex-encoded private keys (unencrypted).

    The used_addr_file should be a file containing a list of used addresses,
    from loyce.club's "all bitcoin addresses ever used" list:
    http://alladdresses.loyce.club/all_Bitcoin_addresses_ever_used_sorted.txt.gz.
    """
    with open(input_json_file, "r") as f:
        priv_key_list = json.load(f)

    if isinstance(used_addr_file, str):
        used_addr_file = Path(used_addr_file)

    addr_to_priv_key = {}
    for priv_key in priv_key_list:
        for compressed in [True, False]:
            addr1 = unencrypted_priv_key_to_address(
                bytes.fromhex(priv_key), compressed=compressed
            )
            addr_to_priv_key[addr1] = priv_key

            addr2 = unencrypted_priv_key_to_address(
                bytes.fromhex(priv_key[::-1]), compressed=compressed
            )
            addr_to_priv_key[addr2] = priv_key

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
    else:
        logger.info("No used addresses found.")


def main():
    parser = argparse.ArgumentParser(
        description="Check a JSON file of private keys for used addresses."
    )
    parser.add_argument(
        "input_json_file",
        type=str,
        help="The JSON file containing private keys.",
    )
    parser.add_argument(
        "used_addr_file",
        type=str,
        help="The file containing used addresses.",
    )
    args = parser.parse_args()

    logger.info(f"Args: {args}")

    check_json_priv_keys_for_used_addr(
        args.input_json_file,
        args.used_addr_file,
    )


if __name__ == "__main__":
    main()
