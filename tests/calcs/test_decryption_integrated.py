import pytest

from pathlib import Path

from armory_lib.types import PyBtcWalletRaw, PyBtcKdfParamsRaw, PyBtcAddressRaw
from armory_lib.calcs import (
    address_hash160_to_address,
    unencrypted_priv_key_to_address,
    key_derivation_function_romix,
    decrypt_aes_cfb,
    encrypted_priv_key_to_address,
)

TEST_ROOT_PATH = Path(__file__).parent.parent


@pytest.fixture
def wallet2_PyBtcWalletRaw() -> PyBtcWalletRaw:
    wallet_bytes = (
        TEST_ROOT_PATH / "test_data/test_wallets/armory_MJUwhWUF_.wallet"
    ).read_bytes()

    return PyBtcWalletRaw.from_bytes(wallet_bytes)


@pytest.fixture
def wallet2_PyBtcAddressRaw() -> PyBtcAddressRaw:
    wallet_bytes = (
        TEST_ROOT_PATH / "test_data/test_wallets/armory_MJUwhWUF_.wallet"
    ).read_bytes()

    # Must add 1083 (to get past PyBtcWalletRaw),
    # then add 1024 (zeros),
    # then add 1 byte (says it's an address),
    # then add 20 bytes (address hash160),
    # then the PyBtcAddressRaw starts
    first_addr_bytes = wallet_bytes[(1083 + 1024 + 1 + 20) :]

    # 0x00 bytes means it's an address
    assert wallet_bytes[1083 + 1024] == 0

    py_addr_obj = PyBtcAddressRaw.from_bytes(first_addr_bytes)
    assert py_addr_obj.validate_all_checksums() is True
    return py_addr_obj


def test_wallet2_hash160_to_address(wallet2_PyBtcAddressRaw):
    py_addr_obj: PyBtcAddressRaw = wallet2_PyBtcAddressRaw
    addr_calc = address_hash160_to_address(py_addr_obj.Address160)
    assert addr_calc == "1FZ4895LkgeqQfuXmD3cpR3m2hjM3DBKrB"


def test_wallet2_decrypt_and_get_address_step_by_step(
    wallet2_PyBtcWalletRaw, wallet2_PyBtcAddressRaw
):
    """Full end-to-end test of decrypting the private key and getting the
    address.
    """
    py_wallet_raw: PyBtcWalletRaw = wallet2_PyBtcWalletRaw
    py_addr_obj: PyBtcAddressRaw = wallet2_PyBtcAddressRaw

    expected_addr = "1FZ4895LkgeqQfuXmD3cpR3m2hjM3DBKrB"

    addr_calc_easy = address_hash160_to_address(py_addr_obj.Address160)
    assert addr_calc_easy == expected_addr

    # Decrypt the private key
    priv_key_encrypted_32_bytes = py_addr_obj.PrivKey
    kdf_info = PyBtcKdfParamsRaw.from_bytes(py_wallet_raw.kdf_parameters)
    assert kdf_info.validate_checksum() is True
    assert kdf_info.memory_requirement == 8 * 1024 * 1024  # 8 MiB
    assert kdf_info.num_iterations == 1

    kdf_output_key = key_derivation_function_romix(
        passphrase=b"0.88_win7_test_11_encr",
        salt=kdf_info.salt,
        memory_requirement_bytes=kdf_info.memory_requirement,
        num_iterations=kdf_info.num_iterations,
    )

    unencrypted_priv_key = decrypt_aes_cfb(
        priv_key_encrypted_32_bytes=priv_key_encrypted_32_bytes,
        kdf_output_key=kdf_output_key,
        init_vector_16_bytes=py_addr_obj.InitVector,
    )

    addr_calc_full = unencrypted_priv_key_to_address(unencrypted_priv_key)
    assert addr_calc_full == expected_addr


def test_wallet2_encrypted_priv_key_to_address(
    wallet2_PyBtcWalletRaw, wallet2_PyBtcAddressRaw
):
    """Full end-to-end test of decrypting the private key and getting the
    address.
    """
    py_wallet_raw: PyBtcWalletRaw = wallet2_PyBtcWalletRaw
    py_addr_obj: PyBtcAddressRaw = wallet2_PyBtcAddressRaw
    kdf_info = PyBtcKdfParamsRaw.from_bytes(py_wallet_raw.kdf_parameters)

    expected_addr = "1FZ4895LkgeqQfuXmD3cpR3m2hjM3DBKrB"

    calc_addr = encrypted_priv_key_to_address(
        priv_key_encrypted_32_bytes=py_addr_obj.PrivKey,
        passphrase="0.88_win7_test_11_encr",
        salt=kdf_info.salt,
        memory_requirement_bytes=kdf_info.memory_requirement,
        num_iterations=kdf_info.num_iterations,
        init_vector_16_bytes=py_addr_obj.InitVector,
    )

    assert calc_addr == expected_addr


@pytest.fixture
def wallet3_PyBtcWalletRaw() -> PyBtcWalletRaw:
    wallet_bytes = (
        TEST_ROOT_PATH
        / "test_data/test_wallets/armory_QPriwP2F_encrypt.wallet"
    ).read_bytes()

    return PyBtcWalletRaw.from_bytes(wallet_bytes)


@pytest.fixture
def wallet3_PyBtcAddressRaw() -> PyBtcAddressRaw:
    wallet_bytes = (
        TEST_ROOT_PATH
        / "test_data/test_wallets/armory_QPriwP2F_encrypt.wallet"
    ).read_bytes()

    # Note: This start offset is way later than in v0.88 wallets. Weird.
    start_offset = int("308C", 16)
    first_addr_bytes = wallet_bytes[start_offset + 20 :]

    # 0x00 bytes means it's an address
    assert wallet_bytes[start_offset - 1] == 0

    py_addr_obj = PyBtcAddressRaw.from_bytes(first_addr_bytes)
    assert py_addr_obj.validate_all_checksums() is True
    return py_addr_obj


def test_wallet3_encrypted_priv_key_to_address(
    wallet3_PyBtcWalletRaw, wallet3_PyBtcAddressRaw
):
    """Full end-to-end test of decrypting the private key and getting the
    address.
    """
    py_wallet_raw: PyBtcWalletRaw = wallet3_PyBtcWalletRaw
    py_addr_obj: PyBtcAddressRaw = wallet3_PyBtcAddressRaw
    kdf_info = PyBtcKdfParamsRaw.from_bytes(py_wallet_raw.kdf_parameters)

    expected_addr = "1CLkV6YCTLDPCtR22Y89hdDQYCKNiRD5An"

    # Only one iteration for this wallet; was hoping it would be more.
    assert kdf_info.num_iterations == 1
    assert kdf_info.memory_requirement == 64 * 1024 * 1024  # 64 MiB
    assert (
        py_addr_obj.Address160.hex()
        == "7c6595fa2e57172371287cde17edff40917d4faf"
    )
    assert address_hash160_to_address(py_addr_obj.Address160) == expected_addr

    calc_addr = encrypted_priv_key_to_address(
        priv_key_encrypted_32_bytes=py_addr_obj.PrivKey,
        passphrase="0.96.5_win7_test_20_encr_highiter",
        salt=kdf_info.salt,
        memory_requirement_bytes=kdf_info.memory_requirement,
        num_iterations=kdf_info.num_iterations,
        init_vector_16_bytes=py_addr_obj.InitVector,
    )

    assert calc_addr == expected_addr


@pytest.fixture
def wallet4_PyBtcWalletRaw() -> PyBtcWalletRaw:
    wallet_bytes = (
        TEST_ROOT_PATH
        / "test_data/test_wallets/armory_2ma44ZAQw_encrypt.wallet"
    ).read_bytes()

    return PyBtcWalletRaw.from_bytes(wallet_bytes)


@pytest.fixture
def wallet4_PyBtcAddressRaw() -> PyBtcAddressRaw:
    wallet_bytes = (
        TEST_ROOT_PATH
        / "test_data/test_wallets/armory_2ma44ZAQw_encrypt.wallet"
    ).read_bytes()

    # Note: This start offset is way later than in v0.88 wallets. Weird.
    start_offset = int("43B2", 16)
    first_addr_bytes = wallet_bytes[start_offset + 20 :]

    # 0x00 bytes means it's an address
    assert wallet_bytes[start_offset - 1] == 0

    py_addr_obj = PyBtcAddressRaw.from_bytes(first_addr_bytes)
    assert py_addr_obj.validate_all_checksums() is True
    return py_addr_obj


def test_wallet4_encrypted_priv_key_to_address(
    wallet4_PyBtcWalletRaw, wallet4_PyBtcAddressRaw
):
    """Full end-to-end test of decrypting the private key and getting the
    address.

    Wallet 4 (armory_2ma44ZAQw_encrypt.wallet) was generated with a KDF
    computation time of 55 seconds. Despite its low memory requirement of
    1 MiB, it takes a while to decrypt the private key.
    """
    py_wallet_raw: PyBtcWalletRaw = wallet4_PyBtcWalletRaw
    py_addr_obj: PyBtcAddressRaw = wallet4_PyBtcAddressRaw
    kdf_info = PyBtcKdfParamsRaw.from_bytes(py_wallet_raw.kdf_parameters)

    print(
        "wallet4: "
        f"memory_requirement: {kdf_info.memory_requirement:,} bytes, "
        f"num_iterations: {kdf_info.num_iterations}"
    )

    expected_addr = "17Rukv6zX1aonwQgRCt8bLX37RKXAc3Y13"

    # Only one iteration for this wallet; was hoping it would be more.
    assert kdf_info.num_iterations == 1732  # intense
    assert kdf_info.memory_requirement == 1 * 1024 * 1024  # 1 MiB
    assert (
        py_addr_obj.Address160.hex()
        == "4686c6f9cdb2fd2038a9d1247fbf025cf946846b"
    )
    assert address_hash160_to_address(py_addr_obj.Address160) == expected_addr

    calc_addr = encrypted_priv_key_to_address(
        priv_key_encrypted_32_bytes=py_addr_obj.PrivKey,
        passphrase="0.96.5_win7_test_22_encr_highiter",
        salt=kdf_info.salt,
        memory_requirement_bytes=kdf_info.memory_requirement,
        num_iterations=kdf_info.num_iterations,
        init_vector_16_bytes=py_addr_obj.InitVector,
    )

    assert calc_addr == expected_addr
