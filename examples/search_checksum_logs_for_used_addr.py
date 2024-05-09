"""\
An example which searches a 'armory_wallet_checksum_searcher' log file for
unencrypted private keys which lead to used addresses.

To test this script, you can run the following from the repo root:

# unencrypted, should find a row (addr=1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm)
python examples/search_checksum_logs_for_used_addr.py tests/test_data/armory_wallet_checksum_searcher_demos/31hTA1aRV.wallet.log tests/test_data/armory_wallet_checksum_searcher_demos/fake_addr_list.txt  # noqa

# old, encrypted, should find no rows for PKs, but should find the address
# (addr=1FZ4895LkgeqQfuXmD3cpR3m2hjM3DBKrB)
python examples/search_checksum_logs_for_used_addr.py tests/test_data/armory_wallet_checksum_searcher_demos/MJUwhWUF.wallet.log tests/test_data/armory_wallet_checksum_searcher_demos/fake_addr_list.txt  # noqa

# new, encrypted, should find no rows for PKs, but should find the address
# (addr=1CLkV6YCTLDPCtR22Y89hdDQYCKNiRD5An)
python examples/search_checksum_logs_for_used_addr.py tests/test_data/armory_wallet_checksum_searcher_demos/QPriwP2F.wallet.log tests/test_data/armory_wallet_checksum_searcher_demos/fake_addr_list.txt  # noqa

"""

import argparse
from pathlib import Path
from dataclasses import dataclass

from loguru import logger
import polars as pl
from used_addr_check import search_multiple_in_file

from armory_lib.specific_parsing import (
    read_checksum_log_into_df,
    log_checksum_summary,
)
from armory_lib.calcs import (
    unencrypted_priv_key_to_address,
    address_hash160_to_address,
)


@dataclass
class StatusForAddress:
    address: str
    # TODO: maybe has_priv_key: bool = False
    found_by_hash160: bool = False
    found_by_unencrypted_private_key: bool = False
    found_by_encrypted_private_key: bool = False
    encryption_passphrase: str | None = None
    is_used: bool = False

    @classmethod
    def from_dict(cls, d: dict):
        return cls(**d)

    def update(self, new_vals: dict):
        for key, val in new_vals.items():
            setattr(self, key, val)

    def to_dict(self):
        return {
            "address": self.address,
            "found_by_hash160": self.found_by_hash160,
            "found_by_unencrypted_private_key": self.found_by_unencrypted_private_key,  # noqa
            "found_by_encrypted_private_key": self.found_by_encrypted_private_key,  # noqa
            "encryption_passphrase": self.encryption_passphrase,
            "is_used": self.is_used,
        }


def check_log_for_used_addrs(
    input_log_file: str | Path,
    used_addr_file: str | Path,
):
    """Check a 'armory_wallet_checksum_searcher' log file for used addresses.

    The used_addr_file should be a file containing a list of used addresses,
    from loyce.club's "all bitcoin addresses ever used" list:
    http://alladdresses.loyce.club/all_Bitcoin_addresses_ever_used_sorted.txt.gz.
    """

    df_log = read_checksum_log_into_df(input_log_file)
    logger.info(f"Loaded {len(df_log):,} checksum passes from the log file.")

    log_checksum_summary(df_log)

    if isinstance(used_addr_file, str):
        used_addr_file = Path(used_addr_file)

    # Create the main store of addresses
    addr_store: dict[str, StatusForAddress] = {}

    # Add addresses by hash160 (length=20)
    df_log_20 = df_log.filter(pl.col("chunk_length") == pl.lit(20))
    logger.info(
        f"Filtered to {len(df_log_20):,} checksum passes with 20-byte chunks."
    )
    hash160_list = df_log_20["chunk_hex_str"].to_list()
    for hash160 in hash160_list:
        addr = address_hash160_to_address(bytes.fromhex(hash160))
        if addr not in addr_store:
            addr_store[addr] = StatusForAddress(address=addr)
        addr_store[addr].found_by_hash160 = True
    logger.info(f"Added addrs by hash160 (len=20 bytes): {len(addr_store)=:,}")

    # Add addresses by unencrypted private key (length=32)
    df_log_32 = df_log.filter(pl.col("chunk_length") == pl.lit(32))
    logger.info(
        f"Filtered to {len(df_log_32):,} checksum passes with 32-byte chunks."
    )
    priv_key_list = df_log_32["chunk_hex_str"].to_list()
    for priv_key in priv_key_list:
        addr = unencrypted_priv_key_to_address(bytes.fromhex(priv_key))
        if addr not in addr_store:
            addr_store[addr] = StatusForAddress(address=addr)
        addr_store[addr].found_by_unencrypted_private_key = True
    logger.info(
        f"Added addrs by unencrypted private key (len=32 bytes): "
        f"{len(addr_store)=:,}"
    )

    # Add addresses by encrypted private key (length=32)
    # TODO: implement this

    logger.info(
        f"Found {len(addr_store):,} potential addresses in the log file. "
        f"Searching in {used_addr_file}..."
    )

    # Search for used addresses, and update the StatusForAddress objects
    found_addr_list = search_multiple_in_file(
        used_addr_file,
        list(addr_store.keys()),
    )
    for addr in found_addr_list:
        addr_store[addr].is_used = True

    # Print the results
    if found_addr_list:
        for addr in found_addr_list:
            logger.info(f"Found used address: {addr}")
            logger.info(f"{addr_store[addr]}")

        df_result = pl.DataFrame(
            [addr_store[addr].to_dict() for addr in found_addr_list]
        )
        logger.info(f"df_result (all, including unused): {df_result}")

        df_result_used = df_result.filter(pl.col("is_used") == pl.lit(True))
        logger.info(f"df_result_used: {df_result_used}")
        logger.info(
            f"Used addresses found: {df_result_used['address'].to_list()}"
        )
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

    check_log_for_used_addrs(
        args.input_log_file,
        args.used_addr_file,
    )


if __name__ == "__main__":
    main()
