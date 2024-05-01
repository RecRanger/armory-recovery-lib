import pytest

from pathlib import Path

from armory_lib.types import PyBtcWalletRaw, PyBtcKdfParamsRaw, PyBtcAddressRaw
from armory_lib.calcs import (
    address_hash160_to_address,
    unencrypted_priv_key_to_address_hash160,
    unencrypted_priv_key_to_address,
    key_derivation_function_romix,
    decrypt_aes_cfb,
)

TEST_ROOT_PATH = Path(__file__).parent.parent


def test_wallet1_hash160_to_address():
    # from armory_31hTA1aRV_.wallet = wallet1
    wallet_1_real_address_hash160_bytes: bytes = bytes.fromhex(
        "7b128f58ea5a7bed44ef4f81f54cdf004cb96c90"
    )
    wallet_1_real_address: str = "1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm"

    addr_calc = address_hash160_to_address(wallet_1_real_address_hash160_bytes)
    assert addr_calc == wallet_1_real_address


def test_wallet1_unencrypted_priv_key_to_address_1():
    # from armory_31hTA1aRV_.wallet = wallet1
    priv_key_hex = (
        "26797662f706b31f4ab3b3b6c293395a31540e935d54c3f80f5d43ca3ef5253d"
    )
    priv_key_bytes = bytes.fromhex(priv_key_hex)

    wallet_1_real_address_hash160_bytes: bytes = bytes.fromhex(
        "7b128f58ea5a7bed44ef4f81f54cdf004cb96c90"
    )
    addr160_calc = unencrypted_priv_key_to_address_hash160(priv_key_bytes)
    assert addr160_calc == wallet_1_real_address_hash160_bytes

    wallet_1_real_address: str = "1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm"
    addr_calc = unencrypted_priv_key_to_address(priv_key_bytes)
    assert addr_calc == wallet_1_real_address
