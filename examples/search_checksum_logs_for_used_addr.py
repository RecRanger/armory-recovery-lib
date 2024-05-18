"""\
An example which searches a 'armory_wallet_checksum_searcher' log file for
unencrypted private keys which lead to used addresses.

To test this script, you can run the following from the repo root:

# unencrypted, should find a row (addr=1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm)
python examples/search_checksum_logs_for_used_addr.py tests/test_data/armory_wallet_checksum_searcher_demos/31hTA1aRV.wallet.log tests/test_data/armory_wallet_checksum_searcher_demos/fake_addr_list.txt  # noqa

# old, encrypted, should find no rows for PKs, but should find the address
# (addr=1FZ4895LkgeqQfuXmD3cpR3m2hjM3DBKrB)
python examples/search_checksum_logs_for_used_addr.py tests/test_data/armory_wallet_checksum_searcher_demos/MJUwhWUF.wallet.log tests/test_data/armory_wallet_checksum_searcher_demos/fake_addr_list.txt  # noqa

# old, encrypted, password should pass and it should find the encrypted PK
# (addr=1FZ4895LkgeqQfuXmD3cpR3m2hjM3DBKrB)
python examples/search_checksum_logs_for_used_addr.py tests/test_data/armory_wallet_checksum_searcher_demos/MJUwhWUF.wallet.log tests/test_data/armory_wallet_checksum_searcher_demos/fake_addr_list.txt -j tests/test_data/test_wallets/test_password_list.json  # noqa

# new, encrypted, should find no rows for PKs, but should find the address
# (addr=1CLkV6YCTLDPCtR22Y89hdDQYCKNiRD5An)
python examples/search_checksum_logs_for_used_addr.py tests/test_data/armory_wallet_checksum_searcher_demos/QPriwP2F.wallet.log tests/test_data/armory_wallet_checksum_searcher_demos/fake_addr_list.txt  # noqa

"""

import argparse
from pathlib import Path
from dataclasses import dataclass
import json
import itertools
from typing import Any

from loguru import logger
import polars as pl
from tqdm import tqdm
from used_addr_check import search_multiple_in_file

from armory_lib.specific_parsing import (
    read_checksum_log_into_df,
    log_checksum_summary,
    log_checksum_len20_facts,
    log_checksum_len44_facts,
)
from armory_lib.calcs import (
    unencrypted_priv_key_to_address,
    address_hash160_to_address,
    public_key_to_address,
    key_derivation_function_romix_PyBtcKdfParamsMinimal,
    decrypt_aes_cfb,
)
from armory_lib.types.py_btc_kdf_params import PyBtcKdfParamsMinimal


@dataclass
class StatusForAddress:
    address: str
    # TODO: maybe has_priv_key: bool = False
    found_by_hash160: bool = False
    found_by_pub_key_65: bool = False
    found_by_unencrypted_private_key: bool = False
    found_by_encrypted_private_key: bool = False
    encryption_passphrase: str | None = None
    is_used: bool = False
    encryption_backtrace_data: dict[str, Any] | None = None

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
            "found_by_pub_key_65": self.found_by_pub_key_65,
            "found_by_unencrypted_private_key": self.found_by_unencrypted_private_key,  # noqa
            "found_by_encrypted_private_key": self.found_by_encrypted_private_key,  # noqa
            "encryption_passphrase": self.encryption_passphrase,
            "is_used": self.is_used,
            "encryption_backtrace_data": self.encryption_backtrace_data,
        }


def check_log_for_used_addrs(
    input_log_file: str | Path,
    used_addr_file: str | Path,
    password_list: list[str] | None = None,
):
    """Check a 'armory_wallet_checksum_searcher' log file for used addresses.

    The used_addr_file should be a file containing a list of used addresses,
    from loyce.club's "all bitcoin addresses ever used" list:
    http://alladdresses.loyce.club/all_Bitcoin_addresses_ever_used_sorted.txt.gz.
    """
    if password_list:
        logger.info(f"Using password list of length {len(password_list):,}.")
    else:
        logger.info(
            "No password list provided. Skipping encrypted private keys."
        )

    df_log = read_checksum_log_into_df(input_log_file)
    logger.info(f"Loaded {len(df_log):,} checksum passes from the log file.")

    log_checksum_summary(df_log)
    log_checksum_len20_facts(df_log)
    log_checksum_len44_facts(df_log)

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

    # Add addresses by public key (length=65)
    df_log_65 = df_log.filter(pl.col("chunk_length") == pl.lit(65))
    logger.info(
        f"Filtered to {len(df_log_65):,} checksum passes with 65-byte chunks."
    )
    pub_key_list = df_log_65["chunk_bytes"].to_list()
    for pub_key in pub_key_list:
        try:
            addr = public_key_to_address(pub_key)
        except Exception:
            # sometimes, this step fails if it's an invalid public key
            continue
        if addr not in addr_store:
            addr_store[addr] = StatusForAddress(address=addr)
        addr_store[addr].found_by_pub_key_65 = True
    logger.info(
        f"Added addrs by public key (len=65 bytes): {len(addr_store)=:,}"
    )

    # Add addresses by unencrypted private key (length=32)
    df_log_32 = df_log.filter(pl.col("chunk_length") == pl.lit(32))
    logger.info(
        f"Filtered to {len(df_log_32):,} checksum passes with 32-byte chunks."
    )
    priv_key_list = df_log_32["chunk_hex_str"].to_list()
    for priv_key_src in priv_key_list:
        addr = unencrypted_priv_key_to_address(bytes.fromhex(priv_key_src))
        if addr not in addr_store:
            addr_store[addr] = StatusForAddress(address=addr)
        addr_store[addr].found_by_unencrypted_private_key = True
    logger.info(
        f"Added addrs by unencrypted private key (len=32 bytes): "
        f"{len(addr_store)=:,}"
    )

    # Add addresses by encrypted private key (length=32)
    if password_list:
        raise NotImplementedError(
            "Encrypted private key search not implemented."
        )
        bytes16_iv_list = df_log.filter(pl.col("chunk_length") == pl.lit(16))[
            "chunk_hex_str"
        ].to_list()
        bytes44_kdf_params_list = df_log.filter(
            pl.col("chunk_length") == pl.lit(44)
        )["chunk_hex_str"].to_list()
        kdf_params_list = [
            PyBtcKdfParamsMinimal.from_bytes(bytes.fromhex(b))
            for b in bytes44_kdf_params_list
        ]
        logger.info(f"Loaded {len(kdf_params_list):,} KDF params.")

        # naive approach: all passwords, all kdf, all IVs, all priv keys
        # key: password, value: kdf_output
        def safe_kdf(
            passphrase: str, kdf_params: PyBtcKdfParamsMinimal
        ) -> bytes:
            try:
                key_derivation_function_romix_PyBtcKdfParamsMinimal(
                    passphrase=passphrase,
                    kdf_params=kdf_params,
                )
            except Exception as e:
                logger.error(
                    f"Error with passphrase: {passphrase}, kdf_params: {kdf_params}: {e}"  # noqa
                )
                return None

        # TODO: filter out the invalid KDF params early-on (in-range iter/mem,
        #   salt is sufficiently random, etc.)
        # TODO: check if we can expect num_iterations to ALWAYS be 1
        # FIXME: need a different data structure to carry forward the password,
        #   with the generated key, while allowing multiple passphrases
        # FIXME: ^ idea: maybe just flip the key-value order
        kdf_output_list: dict[str:bytes] = {
            password: safe_kdf(
                passphrase=password,
                kdf_params=kdf_params,
            )
            for password, kdf_params in tqdm(
                itertools.product(password_list, kdf_params_list),
                total=len(password_list) * len(kdf_params_list),
                desc="KDF (password x kdf_params)",
            )
        }
        len_incl_nulls = len(kdf_output_list.keys())
        kdf_output_list = {
            password: kdf_output
            for password, kdf_output in kdf_output_list.items()
            if kdf_output is not None
        }
        logger.info(
            f"Generated {len(kdf_output_list):,} KDF outputs "
            "(passwords x kdf_params). "
            f"Skipped {len_incl_nulls - len(kdf_output_list):,} due to errors."
        )
        for priv_key_src, iv in tqdm(
            itertools.product(priv_key_list, bytes16_iv_list),
            total=len(priv_key_list) * len(bytes16_iv_list),
            desc="Decrypting (priv_key x iv x password_kdf)",
        ):
            for password, kdf_output in kdf_output_list.items():
                addr = unencrypted_priv_key_to_address(
                    decrypt_aes_cfb(
                        priv_key_encrypted_32_bytes=bytes.fromhex(
                            priv_key_src
                        ),
                        kdf_output_key=kdf_output,
                        init_vector_16_bytes=iv,
                    )
                )
                if addr not in addr_store:
                    addr_store[addr] = StatusForAddress(address=addr)
                addr_store[addr].found_by_encrypted_private_key = True
                addr_store[addr].encryption_passphrase = password
                addr_store[addr].encryption_backtrace_data = {
                    "iv": iv,
                    "kdf_output": kdf_output,
                    "priv_key_src": priv_key_src,  # from log file
                    # didn't store the kdf_params, but that's fine
                }
    else:
        logger.info(
            "No password list provided. Skipping encrypted private keys."
        )
    logger.info(f"Added addrs by encrypted private key: {len(addr_store)=:,}")

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

    # TODO: show file name(s) of where results came from, offsets, etc.
    # Print the results
    if found_addr_list:
        for addr in found_addr_list:
            logger.info(f"Found used address: {addr}")
            logger.info(f"{addr_store[addr]}")

        df_result = pl.DataFrame([x.to_dict() for x in addr_store.values()])
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
    parser.add_argument(
        "-j",
        "--json-password-list",
        type=str,
        default=None,
        dest="json_password_list",
        help="A JSON file with a list of strings, each a possible password.",
    )
    args = parser.parse_args()

    # read the password list
    if args.json_password_list:
        with open(args.json_password_list, "r") as f:
            password_list = json.load(f)
    else:
        password_list = None

    check_log_for_used_addrs(
        args.input_log_file,
        args.used_addr_file,
        password_list=password_list,
    )


if __name__ == "__main__":
    main()
