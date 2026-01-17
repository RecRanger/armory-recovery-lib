import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from armory_lib.calcs.keys import unencrypted_priv_key_to_address
from armory_lib.types.py_btc_kdf_params import PyBtcKdfParamsMinimal


def _sha512(data: bytes | bytearray) -> bytes:
    """
    Hashes the given data using the SHA-512 algorithm.

    :param data: The data to hash.
    :return: The hash of the data.
    """
    sha512 = hashlib.sha512()
    sha512.update(data)
    return sha512.digest()


def _key_derivation_function_romix_one_iter(
    passphrase: bytes | bytearray | str,
    salt: bytes | bytearray,
    memory_requirement_bytes: int,
) -> bytes | bytearray:
    """
    Derives a key from a passphrase using a key derivation function (KDF).

    :param passphrase: The passphrase to derive the key from.
    :param salt: A unique salt value.
    :param memory_requirement_bytes: The minimum memory for the KDF, in bytes.
    :return: The derived key (kdf_output_key) [32 bytes].

    Based on the Armory wallet's key derivation function (KDF) implementation:
    `cppForSwig/EncryptionUtils.cpp:KdfRomix().DeriveKey_OneIter(...)`
    """

    # Convert passphrase to bytes if it's a string
    assert isinstance(passphrase, bytes) or isinstance(passphrase, str), (
        "Passphrase must be a bytes or string, not " + str(type(passphrase))
    )
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")

    # Set constant parameters for the KDF
    hash_output_num_bytes = 64  # 64 bytes = 512 bits
    kdf_output_key_len = 32

    # Set intermediate parameters
    sequence_count = memory_requirement_bytes // hash_output_num_bytes
    salted_passphrase = passphrase + salt

    # Prepare the lookup table, init with zeros
    lookup_table = bytearray(memory_requirement_bytes)

    # First hash to seed the lookup table
    lookup_table[:hash_output_num_bytes] = _sha512(salted_passphrase)

    # Compute consecutive hashes of the passphrase
    for n_byte in range(
        0,
        memory_requirement_bytes - hash_output_num_bytes,
        hash_output_num_bytes,
    ):
        lookup_table[
            n_byte + hash_output_num_bytes : n_byte + 2 * hash_output_num_bytes
        ] = _sha512(lookup_table[n_byte : n_byte + hash_output_num_bytes])

    # Start lookup sequence
    # X = current_hash
    # Y = xor_result
    # V = lookup_hash
    current_hash = lookup_table[
        memory_requirement_bytes
        - hash_output_num_bytes : memory_requirement_bytes
    ]
    # xor_result = bytearray(hash_output_num_bytes)

    # Pure ROMix simulation
    n_lookups = sequence_count // 2
    for _ in range(n_lookups):
        new_index = (
            int.from_bytes(current_hash[-4:], "little") % sequence_count
        )

        # V = lookup_hash
        lookup_hash = lookup_table[
            (new_index * hash_output_num_bytes) : (
                (new_index + 1) * hash_output_num_bytes
            )
        ]

        # "xor X (current_hash) with V (lookup_hash),
        # and store the result in X (current_hash)"
        xor_result_int = int.from_bytes(current_hash, "little")
        lookup_hash_int = int.from_bytes(lookup_hash, "little")
        xor_result = (xor_result_int ^ lookup_hash_int).to_bytes(
            hash_output_num_bytes, "little"
        )
        current_hash = _sha512(xor_result)

    # Truncate the final result to get the final key
    return current_hash[:kdf_output_key_len]


def _test_do_single_iter_demo():
    test_data: dict = {
        "niter": 1,
        "pass_len_bytes": 0,
        "mem": 128,  # very tiny, easier debug
        "pass": "31323335",  # b"1235"
        "salt": "68777977736973737871626966786d61666a6c7966676661667173787369726f",  # noqa
        "out": "573b1f633158904395736403563aaaf4a0c766478d75eb453ae392a50f350da2",  # noqa
    }
    passphrase = bytes.fromhex(test_data["pass"])
    salt = bytes.fromhex(test_data["salt"])
    memory_requirement = test_data["mem"]
    assert test_data["niter"] == 1
    expected_output = bytes.fromhex(test_data["out"])

    kdf_output_key = _key_derivation_function_romix_one_iter(
        passphrase=passphrase,
        salt=salt,
        memory_requirement_bytes=memory_requirement,
    )

    assert kdf_output_key.hex() == expected_output.hex()


def key_derivation_function_romix(
    passphrase: bytes | bytearray | str,
    salt: bytes | bytearray,
    memory_requirement_bytes: int,
    num_iterations: int = 1,
) -> bytes | bytearray:
    """
    Derives a key from a passphrase using a key derivation function (KDF).

    :param passphrase: The passphrase to derive the key from.
    :param salt: A unique salt value.
    :param memory_requirement_bytes: The minimum memory for the KDF, in bytes.
    :param num_iterations: The number of iterations to run the KDF.
    :return: The derived key (kdf_output_key) [32 bytes].

    Based on the Armory wallet's key derivation function (KDF) implementation:
    `cppForSwig/EncryptionUtils.cpp:KdfRomix().DeriveKey_OneIter(...)`
    """
    if memory_requirement_bytes > 1024 * 1024 * 128:
        raise ValueError("Memory requirement too high, limit is 128 MiB")
    elif memory_requirement_bytes < 1024:
        raise ValueError("Memory requirement too low, must be at least 1 KiB")

    if num_iterations < 1:
        raise ValueError("Number of iterations must be at least 1")
    elif num_iterations > 1732 + 1:  # 1732 is the wallet4 test num
        raise ValueError("Number of iterations too high, limit is 1732")

    kdf_output_key: None | bytes | bytearray = None

    for _ in range(num_iterations):
        # Perform the KDF for the specified number of iterations
        kdf_output_key = _key_derivation_function_romix_one_iter(
            passphrase=(
                passphrase if kdf_output_key is None else kdf_output_key
            ),
            salt=salt,
            memory_requirement_bytes=memory_requirement_bytes,
        )

    assert isinstance(kdf_output_key, (bytes, bytearray))
    return kdf_output_key


def key_derivation_function_romix_PyBtcKdfParamsMinimal(
    passphrase: bytes | bytearray | str,
    kdf_params: PyBtcKdfParamsMinimal,
) -> bytes | bytearray:
    """
    Derives a key from a passphrase using a key derivation function (KDF).

    :param passphrase: The passphrase to derive the key from.
    :param kdf_params: The KDF parameters.
    :return: The derived key (kdf_output_key).
    """
    return key_derivation_function_romix(
        passphrase=passphrase,
        salt=kdf_params.salt,
        memory_requirement_bytes=kdf_params.memory_requirement,
        num_iterations=kdf_params.num_iterations,
    )


def decrypt_aes_cfb(
    priv_key_encrypted_32_bytes: bytes | bytearray,
    kdf_output_key: bytes | bytearray,
    init_vector_16_bytes: bytes | bytearray,
) -> bytes | bytearray:
    """
    Decrypts data using AES in CFB mode.
    Used in the Armory wallet's decryption process,
        where the Passphrase is used to generate kdf_output_key.

    :param priv_key_encrypted_32_bytes: The encrypted private key (32 bytes).
    :param kdf_output_key: The key derived from a KDF, used as the AES key.
    :param init_vector_16_bytes: The initialization vector (16 bytes).
    :return: The decrypted data.
    """
    # Create a Cipher object with the given key and IV
    cipher = Cipher(
        algorithms.AES(kdf_output_key),
        modes.CFB(init_vector_16_bytes),
        backend=default_backend(),
    )

    # Create a decryptor object
    decryptor = cipher.decryptor()

    # Perform decryption and return the result
    return decryptor.update(priv_key_encrypted_32_bytes) + decryptor.finalize()


def encrypted_priv_key_to_address(
    priv_key_encrypted_32_bytes: bytes | bytearray,
    passphrase: str,
    salt: bytes | bytearray,
    memory_requirement_bytes: int,
    num_iterations: int,
    init_vector_16_bytes: bytes | bytearray,
):
    kdf_output_key = key_derivation_function_romix(
        passphrase=passphrase,
        salt=salt,
        memory_requirement_bytes=memory_requirement_bytes,
        num_iterations=num_iterations,
    )
    unencrypted_priv_key = decrypt_aes_cfb(
        priv_key_encrypted_32_bytes=priv_key_encrypted_32_bytes,
        kdf_output_key=kdf_output_key,
        init_vector_16_bytes=init_vector_16_bytes,
    )
    address = unencrypted_priv_key_to_address(unencrypted_priv_key)
    return address


# if __name__ == "__main__":
#     _test_do_single_iter_demo()
