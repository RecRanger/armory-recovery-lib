# armory-recovery-lib (`armory_lib`)

Python library and tools for recovering Armory Bitcoin Wallets

[![PyPI version](https://img.shields.io/pypi/v/armory-lib.svg)](https://pypi.org/project/armory-lib/)
[![Python versions](https://img.shields.io/pypi/pyversions/armory-lib.svg)](https://pypi.org/project/armory-lib/)
[![License](https://img.shields.io/pypi/l/armory-lib.svg)](https://pypi.org/project/armory-lib/)
[![Downloads](https://img.shields.io/pypi/dm/armory-lib.svg)](https://pypi.org/project/armory-lib/)

## Example

```python
# Run: uv add armory-lib

from armory_lib.calcs import bitcoin_addr_to_armory_wallet_id

print(bitcoin_addr_to_armory_wallet_id("1CDkMAThcNS4hMZexDiwZF6SJ9gzYmqVgm"))
# "31hTA1aRV"
```

## Other Requirements

```bash
sudo apt-get install libgmp3-dev ripgrep
```

