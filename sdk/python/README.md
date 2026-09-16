# Python DCP sketch (`dcp_sdk.py`)

**Demo only — not TDCP protocol parity.**

This module is a small AES-GCM + associated-data sketch (hardware id + expiry as AAD). It does **not** implement:

- TDCP package envelope / AAD schema
- Authorization Oracle or ECDSA grants
- Gatekeeper, replay, revocation, or View-Once
- ULTRA_CRITICAL A/B/C

## Quick demo

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
python3 - <<'PY'
from dcp_sdk import DCPEngine
import os
engine = DCPEngine(os.urandom(32))
pkg, exp = engine.forjar_activo(b"hello", "device-1", 60)
print(engine.abrir_activo(pkg, "device-1", exp))
PY
```

For the real reference protocol, use the TypeScript sources under `src/core`, `src/oracle`, and `src/gatekeeper`.
