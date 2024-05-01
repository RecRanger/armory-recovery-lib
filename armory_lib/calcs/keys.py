import bitcoinlib


# Docs: https://bitcoinlib.readthedocs.io/en/latest/source/bitcoinlib.keys.html


def address_hash160_to_address(hash160: bytes) -> str:
    addr = bitcoinlib.keys.Address(
        hashed_data=hash160,
        compressed=False,
        script_type="p2pkh",  # default, but explicit
        witness_type="legacy",  # default, but explicit
    )
    return addr.address


def unencrypted_priv_key_to_address_hash160(priv_key: bytes) -> bytes:
    lib_key = bitcoinlib.keys.Key(priv_key, is_private=True, compressed=False)
    return lib_key.hash160


def unencrypted_priv_key_to_address(priv_key: bytes) -> str:
    lib_key = bitcoinlib.keys.Key(priv_key, is_private=True, compressed=False)
    return lib_key.address()
