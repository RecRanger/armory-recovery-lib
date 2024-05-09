from bitcoinlib.keys import Key
import base58

from armory_lib.calcs.hashes import compute_checksum

# Docs: https://bitcoinlib.readthedocs.io/en/latest/source/bitcoinlib.keys.html

NETWORK_BYTE = bytes.fromhex("00")


def address_hash160_to_address(hash160: bytes) -> str:
    # addr = Address(
    #     hashed_data=hash160,
    #     compressed=False,  # appears to be irrelevant
    #     script_type="p2pkh",  # default, but explicit
    #     witness_type="legacy",  # default, but explicit
    # )
    # return addr.address
    assert len(hash160) == 20

    # don't forget to include the checksum before hashing
    checksum = compute_checksum(NETWORK_BYTE + hash160)
    return base58.b58encode(NETWORK_BYTE + hash160 + checksum).decode("ascii")


def address_to_address_hash160(addr: str) -> bytes:
    """Convert a Bitcoin address to a hash160.
    Returns 20 bytes.
    """
    # lib_addr = Address.import_address(
    #     addr,
    #     compressed=False,  # appears to be irrelevant
    # )
    # return lib_addr.hash_bytes
    addr_decoded = base58.b58decode(addr)
    return addr_decoded[1:21]  # skip network byte, skip checksum


def unencrypted_priv_key_to_address_hash160(
    priv_key: bytes, compressed: bool = False
) -> bytes:
    """Convert an unencrypted private key to a Bitcoin address's hash160.
    Expects a 32-byte private key.
    For old Armory wallets, compressed=False.
    """
    lib_key = Key(priv_key, is_private=True, compressed=compressed)
    return lib_key.hash160


def unencrypted_priv_key_to_address(
    priv_key: bytes, compressed: bool = False
) -> str:
    """Convert an unencrypted private key to a Bitcoin address.
    Expects a 32-byte private key.
    For old Armory wallets, compressed=False.
    """
    lib_key = Key(priv_key, is_private=True, compressed=compressed)
    return lib_key.address()
