from dataclasses import dataclass


@dataclass
class PyBtcAddressRaw:
    Address160: bytes
    AddressChk: bytes
    AddrVersion: bytes
    Flags: bytes
    ChainCode: bytes
    ChainChk: bytes
    ChainIndex: bytes
    ChainDepth: bytes
    InitVector: bytes
    InitVectorChk: bytes
    PrivKey: bytes
    PrivKeyChk: bytes
    PublicKey: bytes
    PubKeyChk: bytes
    FirstTime: bytes
    LastTime: bytes
    FirstBlock: bytes
    LastBlock: bytes

    @classmethod
    def from_bytes(cls, byte_string) -> "PyBtcAddressRaw":
        return cls(
            Address160=byte_string[0:20],  # 20 bytes
            AddressChk=byte_string[20:24],  # 4 bytes
            AddrVersion=byte_string[24:28],
            Flags=byte_string[28:36],
            ChainCode=byte_string[36:68],  # 32 bytes
            ChainChk=byte_string[68:72],  # 4 bytes
            ChainIndex=byte_string[72:80],
            ChainDepth=byte_string[80:88],
            InitVector=byte_string[88:104],  # 16 bytes
            InitVectorChk=byte_string[104:108],  # 4 bytes
            PrivKey=byte_string[108:140],  # 32 bytes
            PrivKeyChk=byte_string[140:144],  # 4 bytes
            PublicKey=byte_string[144:209],  # 65 bytes
            PubKeyChk=byte_string[209:213],
            FirstTime=byte_string[213:221],
            LastTime=byte_string[221:229],
            FirstBlock=byte_string[229:233],
            LastBlock=byte_string[233:237],
        )

    def to_hex_dict(self) -> dict[str, str]:
        return {
            "Address160": self.Address160.hex(),
            "AddressChk": self.AddressChk.hex(),
            "AddrVersion": self.AddrVersion.hex(),
            "Flags": self.Flags.hex(),
            "ChainCode": self.ChainCode.hex(),
            "ChainChk": self.ChainChk.hex(),
            "ChainIndex": self.ChainIndex.hex(),
            "ChainDepth": self.ChainDepth.hex(),
            "InitVector": self.InitVector.hex(),
            "InitVectorChk": self.InitVectorChk.hex(),
            "PrivKey": self.PrivKey.hex(),
            "PrivKeyChk": self.PrivKeyChk.hex(),
            "PublicKey": self.PublicKey.hex(),
            "PubKeyChk": self.PubKeyChk.hex(),
            "FirstTime": self.FirstTime.hex(),
            "LastTime": self.LastTime.hex(),
            "FirstBlock": self.FirstBlock.hex(),
            "LastBlock": self.LastBlock.hex(),
        }

    def to_int_dict(self, only_relevant: bool = True) -> dict[str, int]:
        out = self.to_hex_dict()
        if only_relevant:
            out = {
                k: v
                for k, v in out.items()
                if k in ["FirstTime", "LastTime", "FirstBlock", "LastBlock"]
            }
        out = {k: int(v, 16) for k, v in out.items()}
        return out

    def validate_checksums(self) -> dict[str, bool]:
        from armory_lib.calcs import compute_checksum

        return {
            "AddressChk": compute_checksum(self.Address160) == self.AddressChk,
            "ChainChk": compute_checksum(self.ChainCode) == self.ChainChk,
            "InitVectorChk": (
                compute_checksum(self.InitVector) == self.InitVectorChk
            ),
            "PrivKeyChk": compute_checksum(self.PrivKey) == self.PrivKeyChk,
            "PubKeyChk": compute_checksum(self.PublicKey) == self.PubKeyChk,
        }

    def validate_all_checksums(self) -> bool:
        return all(self.validate_checksums().values())
