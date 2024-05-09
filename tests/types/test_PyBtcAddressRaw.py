from pathlib import Path

from armory_lib.types import PyBtcAddressRaw
from armory_lib.parsing import find_nth_occurrence

TEST_ROOT_PATH = Path(__file__).parent.parent


def test_parse_armory_PyBtcAddressRaw():
    wallet_1_bytes = (
        TEST_ROOT_PATH / "test_data/test_wallets/armory_31hTA1aRV_.wallet"
    ).read_bytes()

    # find the hash160 (start of the PyBtcAddressRaw section)
    wallet_1_start_pos = find_nth_occurrence(
        wallet_1_bytes,
        bytes.fromhex("7b128f58ea5a7bed44ef4f81f54cdf004cb96c90"),
        2,
    )
    wallet_1_obj = PyBtcAddressRaw.from_bytes(
        wallet_1_bytes[wallet_1_start_pos:]
    )

    wallet_1_real_address_hash160_bytes: bytes = bytes.fromhex(
        "7b128f58ea5a7bed44ef4f81f54cdf004cb96c90"
    )
    assert wallet_1_obj.Address160 == wallet_1_real_address_hash160_bytes

    # all checksums should pass
    assert all(wallet_1_obj.validate_checksums().values())

    wallet_expected = {
        "Address160": "7b128f58ea5a7bed44ef4f81f54cdf004cb96c90",
        "AddressChk": "af136457",
        "AddrVersion": "60fecd00",
        "Flags": "0300000000000000",
        "ChainCode": "0083e9f1633c46577000c07942d3c4b9fd8a0d801b8e891e2ad74fb953d78b26",  # noqa
        "ChainChk": "a79551fb",
        "ChainIndex": "0000000000000000",
        "ChainDepth": "ffffffffffffffff",
        "InitVector": "ea1983a824e8bbbbf1b6c0e565d12987",
        "InitVectorChk": "a7a0c002",
        "PrivKey": "26797662f706b31f4ab3b3b6c293395a31540e935d54c3f80f5d43ca3ef5253d",  # noqa
        "PrivKeyChk": "8884a257",
        "PublicKey": "04942f18185628c5a6901116e67eca0b8042e1fdb28fde1c91d6b057a37efe437ad0bd3a32f1770ee8f4e31b87cb81937a9c941f8cfbe142c772f969d323625e93",  # noqa
        "PubKeyChk": "98bf4195",
        "FirstTime": "15c1266600000000",
        "LastTime": "15c1266600000000",
        "FirstBlock": "ffffffff",
        "LastBlock": "00000000",
    }
    validate_expected = {
        "AddressChk": True,
        "ChainChk": True,
        "InitVectorChk": True,
        "PrivKeyChk": True,
        "PubKeyChk": True,
    }

    assert wallet_1_obj.to_hex_dict() == wallet_expected
    assert wallet_1_obj.validate_checksums() == validate_expected
