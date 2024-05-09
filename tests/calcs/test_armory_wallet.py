from armory_lib.calcs import (
    bitcoin_addr_to_armory_unique_id,
    bitcoin_addr_to_armory_wallet_id,
)


def test_bitcoin_addr_to_armory_unique_id():
    assert bitcoin_addr_to_armory_unique_id(
        "1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm"
    ) == bytes.fromhex("ea588f127b00")


def test_bitcoin_addr_to_armory_wallet_id():
    assert (
        bitcoin_addr_to_armory_wallet_id("1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm")
        == "31hTA1aRV"
    )
