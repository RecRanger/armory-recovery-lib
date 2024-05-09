from pathlib import Path

from armory_lib.calcs import (
    address_hash160_to_address,
    address_to_address_hash160,
    public_key_to_address,
    unencrypted_priv_key_to_address_hash160,
    unencrypted_priv_key_to_address,
    compute_checksum,
)
from armory_lib.calcs.hashes import _sha256d

TEST_ROOT_PATH = Path(__file__).parent.parent


def test_wallet1_hash160_to_address():
    # from armory_31hTA1aRV_.wallet = wallet1
    wallet_1_real_address_hash160_bytes: bytes = bytes.fromhex(
        "7b128f58ea5a7bed44ef4f81f54cdf004cb96c90"
    )
    wallet_1_real_address: str = "1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm"

    addr_calc = address_hash160_to_address(wallet_1_real_address_hash160_bytes)
    assert addr_calc == wallet_1_real_address


def test_wallet1_address_to_hash160():
    # from armory_31hTA1aRV_.wallet = wallet1
    wallet_1_real_address_hash160_bytes: bytes = bytes.fromhex(
        "7b128f58ea5a7bed44ef4f81f54cdf004cb96c90"
    )
    wallet_1_real_address: str = "1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm"

    addr160_calc = address_to_address_hash160(wallet_1_real_address)
    assert addr160_calc == wallet_1_real_address_hash160_bytes


def test_wallet1_public_key_to_address():
    public_key_65 = bytes.fromhex(
        "04942f18185628c5a6901116e67eca0b8042e1fdb28fde1c91d6b057a37efe437ad0bd3a32f1770ee8f4e31b87cb81937a9c941f8cfbe142c772f969d323625e93"  # noqa
    )
    wallet_1_real_address: str = "1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm"
    assert public_key_to_address(public_key_65) == wallet_1_real_address


def test_sha256d():
    # Source: https://bitcoin.stackexchange.com/a/32363
    hash160 = bytes.fromhex("00" + "c4c5d791fcb4654a1ef5e03fe0ad3d9c598f9827")
    checksum = bytes.fromhex("4abb8f1a")
    assert _sha256d(hash160)[:4] == checksum
    assert compute_checksum(hash160) == checksum


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
