from dataclasses import dataclass

import base58


@dataclass
class PyBtcWalletRaw:
    file_id: bytes  # 8 bytes -> always '\xbaWALLET\x00'
    version: bytes  # 4 bytes
    magic_bytes: bytes  # 4 bytes
    wallet_flags: bytes  # 8 bytes -> "info about the wallet"

    # First 6 bytes of first address in wallet
    #   (rootAddr25Bytes[:6][::-1]), reversed
    # This is not intended to look like the root addr str
    # and is reversed to avoid having all wallet IDs start
    # with the same characters (since the network byte is front)
    unique_id: bytes  # 6 bytes
    created_date: bytes  # 8 bytes
    short_name: bytes  # 32 bytes
    long_name: bytes  # 256 bytes
    highest_used: bytes  # 8 bytes
    kdf_parameters: bytes  # 256 bytes
    crypto_parameters: bytes  # 256 bytes (all zeros in v1)
    root_key_address: bytes  # 237 bytes
    # Above sums to: 1083 bytes total

    @classmethod
    def from_bytes(cls, byte_string: bytes) -> "PyBtcWalletRaw":
        assert isinstance(byte_string, bytes), "Byte string must be type bytes"
        assert len(byte_string) >= 1083, (
            "Byte string must be >=1083 bytes long"
        )
        return cls(
            file_id=byte_string[0:8],
            version=byte_string[8:12],
            magic_bytes=byte_string[12:16],
            wallet_flags=byte_string[16:24],
            unique_id=byte_string[24:30],
            created_date=byte_string[30:38],
            short_name=byte_string[38:70],
            long_name=byte_string[70:326],
            highest_used=byte_string[326:334],
            kdf_parameters=byte_string[334:590],
            crypto_parameters=byte_string[590:846],
            root_key_address=byte_string[846:1083],
        )

    def to_hex_dict(self) -> dict[str, str]:
        return {
            "file_id": self.file_id.hex(),
            "version": self.version.hex(),
            "magic_bytes": self.magic_bytes.hex(),
            "wallet_flags": self.wallet_flags.hex(),
            "unique_id": self.unique_id.hex(),
            "created_date": self.created_date.hex(),
            "short_name": self.short_name.hex(),
            "long_name": self.long_name.hex(),
            "highest_used": self.highest_used.hex(),
            "kdf_parameters": self.kdf_parameters.hex(),
            "crypto_parameters": self.crypto_parameters.hex(),
            "root_key_address": self.root_key_address.hex(),
        }

    def is_encrypted(self) -> bool:
        encrypted_flag: int = self.wallet_flags[0]  # read the byte
        if encrypted_flag == 0:
            return False
        elif encrypted_flag == 1:
            return True
        else:
            raise ValueError(f"Invalid encrypted flag: {encrypted_flag}")

    @property
    def wallet_id(self) -> str:
        """Returns the wallet ID as a base58 encoded string, as it appears in
        the default wallet filename. ~9 base58 characters long."""
        return base58.b58encode(self.unique_id).decode("ascii")
