"""\
This script generates a list of valuable search terms ("needles") to search
a broken hard drive for, in search of a specific armory wallet.
"""

import argparse

from armory_lib.calcs import (
    bitcoin_addr_to_armory_wallet_id,
    bitcoin_addr_to_armory_unique_id,
    address_to_address_hash160,
    compute_checksum,
)


def generate_valuable_searches(
    wallet_addr: str = "1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm",
):
    wallet_id = bitcoin_addr_to_armory_wallet_id(wallet_addr)
    unique_id = bitcoin_addr_to_armory_unique_id(wallet_addr)

    print(f"Original Address (str): {wallet_addr}")
    print(f"Wallet ID (str): {wallet_id}")
    print(f"Wallet Unique ID (hex): {unique_id.hex()}")

    hash160 = address_to_address_hash160(wallet_addr)
    print("Wallet Hash160 (20 bytes) (hex): " + hash160.hex())
    print(
        "Wallet Hash160 + Checksum (24 bytes) (hex): "
        + (hash160 + compute_checksum(hash160)).hex()
    )


def main():
    parser = argparse.ArgumentParser(
        description="Generate valuable search terms for a broken hard drive."
    )
    parser.add_argument(
        "-a",
        "--addr",
        type=str,
        action="append",
        default=["1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm"],
        help="The Bitcoin address of the wallet to search for.",
    )
    args = parser.parse_args()

    if isinstance(args.addr, str):
        wallet_addr_list = [args.addr]
    elif isinstance(args.addr, list):
        wallet_addr_list = args.addr
    else:
        raise ValueError(f"Invalid wallet address: {args.addr}")

    # Skip the first address (an example address)
    if len(wallet_addr_list) > 1:
        wallet_addr_list = wallet_addr_list[1:]

    for wallet_addr in wallet_addr_list:
        generate_valuable_searches(wallet_addr)

        print("=" * 80)


if __name__ == "__main__":
    main()
