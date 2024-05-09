from pathlib import Path

from armory_lib.types import PyBtcWalletRaw
from armory_lib.parsing import fill_to_length

TEST_ROOT_PATH = Path(__file__).parent.parent


def test_parse_armory_PyBtcAddressRaw_31hTA1aRV():
    wallet_bytes = (
        TEST_ROOT_PATH / "test_data/test_wallets/armory_31hTA1aRV_.wallet"
    ).read_bytes()

    uut = PyBtcWalletRaw.from_bytes(wallet_bytes)

    expected_wallet_name: str = "0.88_win7_test_10_nencr"
    assert uut.short_name.rstrip(b"\0").decode("utf-8") == expected_wallet_name
    assert uut.long_name.rstrip(b"\0").decode("utf-8") == expected_wallet_name
    expected_wallet_name_bytes: bytes = expected_wallet_name.encode("utf-8")

    expected_wallet_id = "31hTA1aRV"
    assert uut.wallet_id == expected_wallet_id

    assert uut.is_encrypted() is False

    wallet_expected_hex_dict = {
        "file_id": "ba57414c4c455400",
        "version": "60fecd00",
        "magic_bytes": "f9beb4d9",
        "wallet_flags": "0000000000000000",
        "unique_id": "ea588f127b00",
        "created_date": "cbc0266600000000",
        "short_name": fill_to_length(
            expected_wallet_name_bytes, b"\0", 32
        ).hex(),
        "long_name": fill_to_length(
            expected_wallet_name_bytes, b"\0", 256
        ).hex(),
        "highest_used": "0000000000000000",
        "kdf_parameters": "00" * 256,
        "crypto_parameters": "00" * 256,
        "root_key_address": "76dcad874f9a774bd8936e5f35d2f2cfcc5a533fa293d38e60fecd0003000000000000000083e9f1633c46577000c07942d3c4b9fd8a0d801b8e891e2ad74fb953d78b26a79551fbffffffffffffffffffffffffffffffff000000000000000000000000000000005df6e0e2aeca5b03afc50eca5e2b469680fc8796169a63dea5e1242872d47574edd1192a3e815e2b049df500f97dbec7417265969c3b16767f0c95cfa5f0d5c4f270417b4f0a1b89d0bdcaf29d12eb6c1b533775e76eb51193a4f12add3e8e460729e88f77f975445a92d75b19ffffffff000000000000000000000000ffffffff00000000",  # noqa
    }

    assert uut.to_hex_dict() == wallet_expected_hex_dict


def test_parse_armory_PyBtcAddressRaw_MJUwhWUF():
    wallet_bytes = (
        TEST_ROOT_PATH / "test_data/test_wallets/armory_MJUwhWUF_.wallet"
    ).read_bytes()

    uut = PyBtcWalletRaw.from_bytes(wallet_bytes)

    expected_wallet_name: str = "0.88_win7_test_11_encr"
    assert uut.short_name.rstrip(b"\0").decode("utf-8") == expected_wallet_name
    assert uut.long_name.rstrip(b"\0").decode("utf-8") == expected_wallet_name
    expected_wallet_name_bytes: bytes = expected_wallet_name.encode("utf-8")

    assert uut.is_encrypted() is True

    wallet_expected_hex_dict = {
        "file_id": "ba57414c4c455400",
        "version": "60fecd00",
        "magic_bytes": "f9beb4d9",
        "wallet_flags": "0100000000000000",
        "unique_id": "28c4ada19f00",
        "created_date": "29c1266600000000",
        "short_name": fill_to_length(
            expected_wallet_name_bytes, b"\0", 32
        ).hex(),
        "long_name": fill_to_length(
            expected_wallet_name_bytes, b"\0", 256
        ).hex(),
        "highest_used": "0000000000000000",
        "kdf_parameters": fill_to_length(
            "000080000000000001000000a7671460d65d64a705ae43e1d45d336ae452a7c8b466db54f466a8cc2add8d0b37c15dc7",
            fill_val="0",
            length=256 * 2,  # two zeros per byte, 256 bytes
        ),
        "crypto_parameters": "00" * 256,
        "root_key_address": "8db96eaacbd50e9ca1c9d354d12e1368f10e27f28eaaa23860fecd000700000000000000f0ac1c5f59ca76c171530ca28e04404744953ee595fe26e13481be54cc97a835ef63989effffffffffffffffffffffffffffffff19b33aa8954a969ad302f793033fe69e2af1f28975cc9880cc55ee332b6e9a867340303d09000bb3c2263690dc3c3fb6466ae33d862fda3f04e944666027c1a956ea9090448cb0d98c3cc1b32aa43a2fbeda47ed0ae86d34a4647e800173ecb4d2b7ecfa7baf50d2fe9e8d9f257bcd2fddd7b139234146b04d057bcb6fffffffff000000000000000000000000ffffffff00000000",  # noqa
    }

    assert uut.to_hex_dict() == wallet_expected_hex_dict
