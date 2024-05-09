from armory_lib.calcs.keys import address_to_address_hash160

import base58

NETWORK_BYTE = bytes.fromhex("00")


def bitcoin_addr_to_armory_unique_id(addr: str) -> bytes:
    """Convert a bitcoin address to an Armory 6-byte wallet unique ID.
    This value is directly from the Armory PyBtcWallet class's unique_id field.
    """

    addr_hash = NETWORK_BYTE + address_to_address_hash160(addr)
    unique_id = addr_hash[:6][::-1]
    return unique_id


def bitcoin_addr_to_armory_wallet_id(addr: str) -> str:
    """Convert a bitcoin address to an Armory wallet ID."""

    unique_id = bitcoin_addr_to_armory_unique_id(addr)
    return base58.b58encode(unique_id).decode("ascii")
