from bitcoinlib.keys import Key, Address


# Docs: https://bitcoinlib.readthedocs.io/en/latest/source/bitcoinlib.keys.html


def address_hash160_to_address(hash160: bytes) -> str:
    addr = Address(
        hashed_data=hash160,
        compressed=False,  # appears to be irrelevant
        script_type="p2pkh",  # default, but explicit
        witness_type="legacy",  # default, but explicit
    )
    return addr.address


def address_to_address_hash160(addr: str) -> bytes:
    lib_addr = Address.import_address(
        addr,
        compressed=False,  # appears to be irrelevant
    )
    return lib_addr.hash_bytes


def unencrypted_priv_key_to_address_hash160(priv_key: bytes) -> bytes:
    lib_key = Key(priv_key, is_private=True, compressed=False)
    return lib_key.hash160


def unencrypted_priv_key_to_address(priv_key: bytes) -> str:
    lib_key = Key(priv_key, is_private=True, compressed=False)
    return lib_key.address()
