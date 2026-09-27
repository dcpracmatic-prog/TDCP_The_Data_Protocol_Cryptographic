#!/usr/bin/env python3
"""
CSG / Sello de Integridad HTTP sidecar for TDCP (stdlib only).

No FastAPI required — uses http.server + cryptography (Ed25519) + SHA3-256.
JSON field names aligned with sello_integridad Rust crate
(https://github.com/dcpracmatic-prog/CSG).

Environment:
  CSG_HOST          default 127.0.0.1
  CSG_PORT          default 8010
  CSG_NOTARIO_NAME  default TDCP-Notario
  CSG_DATA_DIR      default ./data/csg-sidecar

Endpoints:
  GET  /healthz
  GET  /v1/status
  POST /v1/seal     { content_base64, label?, attributes?, proyecto_id?, evento_id? }
  POST /v1/verify   { content_base64, sello }
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

GENESIS_HASH = "0" * 64


def sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


@dataclass
class Sello:
    evento_id: str
    aceptado: bool
    razon: str
    timestamp: int
    hash_contenido: str
    firmante_pub: str
    sello_anterior: str
    cuerpo_hash: str
    firma_notario: str
    schema: str = "csg.sello.v1"
    label: str = ""
    attributes: dict = field(default_factory=dict)
    notario_pub: str = ""
    developmentOnly: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NotarioState:
    def __init__(self, name: str, data_dir: Path | None = None):
        self.name = name
        self.data_dir = data_dir
        self._lock = threading.Lock()
        self.conatus = 0.0
        self.estructura_rota = False
        self.umbral_ruptura = 8
        self.factor_endurecimiento = 1.5
        self.intentos_fallidos = 0
        self.chain_tip = GENESIS_HASH
        self.authorized_signers: dict[str, str] = {}
        self._load_or_create_keys()

    def _load_or_create_keys(self) -> None:
        if self.data_dir:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            key_path = self.data_dir / "notario.ed25519"
            state_path = self.data_dir / "state.json"
            if key_path.exists():
                self._sk = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
            else:
                self._sk = Ed25519PrivateKey.generate()
                key_path.write_bytes(
                    self._sk.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
                key_path.chmod(0o600)
            if state_path.exists():
                st = json.loads(state_path.read_text())
                self.chain_tip = st.get("chain_tip", GENESIS_HASH)
                self.conatus = float(st.get("conatus", 0))
                self.estructura_rota = bool(st.get("estructura_rota", False))
                self.intentos_fallidos = int(st.get("intentos_fallidos", 0))
                self.authorized_signers = st.get("authorized_signers", {})
        else:
            self._sk = Ed25519PrivateKey.generate()

        pub = self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.notario_pub_hex = pub.hex()

        if self.data_dir and (self.data_dir / "firmante.ed25519").exists():
            self._firmante_sk = Ed25519PrivateKey.from_private_bytes(
                (self.data_dir / "firmante.ed25519").read_bytes()
            )
        else:
            self._firmante_sk = Ed25519PrivateKey.generate()
            if self.data_dir:
                p = self.data_dir / "firmante.ed25519"
                p.write_bytes(
                    self._firmante_sk.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
                p.chmod(0o600)

        fpub = self._firmante_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.firmante_pub_hex = fpub.hex()
        if "tdcp" not in self.authorized_signers:
            self.authorized_signers["tdcp"] = self.firmante_pub_hex

    def _persist(self) -> None:
        if not self.data_dir:
            return
        (self.data_dir / "state.json").write_text(
            json.dumps(
                {
                    "chain_tip": self.chain_tip,
                    "conatus": self.conatus,
                    "estructura_rota": self.estructura_rota,
                    "intentos_fallidos": self.intentos_fallidos,
                    "authorized_signers": self.authorized_signers,
                    "notario_name": self.name,
                },
                indent=2,
            )
        )

    def seal(
        self,
        content: bytes,
        *,
        label: str = "tdcp-integrity",
        attributes: dict[str, str] | None = None,
        proyecto_id: str = "tdcp",
        evento_id: str | None = None,
    ) -> Sello:
        with self._lock:
            if self.estructura_rota:
                raise RuntimeError(
                    "EstructuraRota: notario en ruptura estructural; recuperación fuera de banda"
                )

            attributes = attributes or {}
            hash_contenido = sha3_256_hex(content)
            eid = evento_id or f"evt-{int(time.time())}-{secrets.token_hex(4)}"
            ts = int(time.time())
            firmante_pub = self.authorized_signers.get(proyecto_id, self.firmante_pub_hex)
            aceptado = firmante_pub in self.authorized_signers.values()
            razon = "" if aceptado else "FIRMANTE_NO_AUTORIZADO"

            if not aceptado:
                self.intentos_fallidos += 1
                self.conatus = min(100.0, self.conatus * self.factor_endurecimiento + 1.0)
                if self.intentos_fallidos >= self.umbral_ruptura:
                    self.estructura_rota = True
                self._persist()

            cuerpo = {
                "evento_id": eid,
                "aceptado": aceptado,
                "razon": razon,
                "timestamp": ts,
                "hash_contenido": hash_contenido,
                "firmante_pub": firmante_pub,
                "sello_anterior": self.chain_tip,
            }
            cuerpo_hash = sha3_256_hex(canonical_json(cuerpo))
            sig = self._sk.sign(cuerpo_hash.encode("utf-8"))

            sello = Sello(
                evento_id=eid,
                aceptado=aceptado,
                razon=razon,
                timestamp=ts,
                hash_contenido=hash_contenido,
                firmante_pub=firmante_pub,
                sello_anterior=self.chain_tip,
                cuerpo_hash=cuerpo_hash,
                firma_notario=sig.hex(),
                label=label,
                attributes=attributes,
                notario_pub=self.notario_pub_hex,
            )
            if aceptado:
                self.chain_tip = cuerpo_hash
                self.conatus = max(0.0, self.conatus * 0.9)
                self._persist()
            return sello

    def verify(self, content: bytes, sello: dict) -> dict[str, Any]:
        hash_contenido = sha3_256_hex(content)
        checks = {
            "content_digest_match": hash_contenido == sello.get("hash_contenido"),
            "cuerpo_no_alterado": False,
            "firma_notario_valida": False,
            "aceptado": bool(sello.get("aceptado")),
        }
        cuerpo = {
            "evento_id": sello.get("evento_id"),
            "aceptado": sello.get("aceptado"),
            "razon": sello.get("razon", ""),
            "timestamp": sello.get("timestamp"),
            "hash_contenido": sello.get("hash_contenido"),
            "firmante_pub": sello.get("firmante_pub"),
            "sello_anterior": sello.get("sello_anterior"),
        }
        expected_hash = sha3_256_hex(canonical_json(cuerpo))
        checks["cuerpo_no_alterado"] = expected_hash == sello.get("cuerpo_hash")

        notario_pub_hex = sello.get("notario_pub") or self.notario_pub_hex
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(notario_pub_hex))
            pub.verify(
                bytes.fromhex(sello["firma_notario"]),
                sello["cuerpo_hash"].encode("utf-8"),
            )
            checks["firma_notario_valida"] = True
        except Exception:
            checks["firma_notario_valida"] = False

        todo_valido = all(checks.values())
        return {
            "todo_valido": todo_valido,
            "checks": checks,
            "hash_contenido": hash_contenido,
            "schema": sello.get("schema", "csg.sello.v1"),
        }


DATA_DIR = os.environ.get("CSG_DATA_DIR", "./data/csg-sidecar")
notario = NotarioState(
    name=os.environ.get("CSG_NOTARIO_NAME", "TDCP-Notario"),
    data_dir=Path(DATA_DIR),
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[CSG] {self.address_string()} {fmt % args}")

    def _json(self, code: int, body: Any) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/healthz":
            self._json(
                200,
                {
                    "ok": True,
                    "service": "csg-sello-sidecar",
                    "notario": notario.name,
                    "estructura_rota": notario.estructura_rota,
                    "version": "1.0.0",
                },
            )
            return
        if path == "/v1/status":
            self._json(
                200,
                {
                    "notario_name": notario.name,
                    "notario_pub": notario.notario_pub_hex,
                    "firmante_pub": notario.firmante_pub_hex,
                    "chain_tip": notario.chain_tip,
                    "conatus": notario.conatus,
                    "estructura_rota": notario.estructura_rota,
                    "intentos_fallidos": notario.intentos_fallidos,
                },
            )
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON"})
            return

        if path == "/v1/seal":
            content_b64 = body.get("content_base64")
            if not content_b64:
                self._json(400, {"error": "content_base64 required"})
                return
            try:
                content = b64d(content_b64)
            except Exception as e:
                self._json(400, {"error": f"invalid content_base64: {e}"})
                return
            try:
                sello = notario.seal(
                    content,
                    label=body.get("label") or "tdcp-integrity",
                    attributes=body.get("attributes") or {},
                    proyecto_id=body.get("proyecto_id") or "tdcp",
                    evento_id=body.get("evento_id"),
                )
            except RuntimeError as e:
                self._json(503, {"error": str(e)})
                return
            self._json(200, sello.to_dict())
            return

        if path == "/v1/verify":
            content_b64 = body.get("content_base64")
            sello = body.get("sello")
            if not content_b64 or not sello:
                self._json(400, {"error": "content_base64 and sello required"})
                return
            try:
                content = b64d(content_b64)
            except Exception as e:
                self._json(400, {"error": f"invalid content_base64: {e}"})
                return
            self._json(200, notario.verify(content, sello))
            return

        self._json(404, {"error": "not found"})


def main() -> None:
    host = os.environ.get("CSG_HOST", "127.0.0.1")
    port = int(os.environ.get("CSG_PORT", "8010"))
    print(f"[CSG] Notario={notario.name} pub={notario.notario_pub_hex[:16]}…")
    print(f"[CSG] Listening on http://{host}:{port}")
    server = ThreadingHTTPServer((host, port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[CSG] shutdown")
        server.shutdown()


if __name__ == "__main__":
    main()
