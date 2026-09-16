# dcp_sdk.py
import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class DCPEngine:
    """Motor DCP Nativo - Descentralizado y Offline"""
    def __init__(self, master_seed: bytes):
        self.master_key = master_seed
        self.aesgcm = AESGCM(self.master_key)

    def forjar_activo(self, datos_texto_plano: bytes, hardware_id: str, tiempo_vida_segundos: int) -> tuple:
        nonce = os.urandom(12)
        fecha_caducidad = time.time() + tiempo_vida_segundos
        
        # Matriz de anclaje local
        metadatos = f"{hardware_id}|{fecha_caducidad}".encode()
        
        # Cifrado con datos asociados
        paquete_sellado = self.aesgcm.encrypt(nonce, datos_texto_plano, metadatos)
        return (nonce + paquete_sellado, fecha_caducidad)

    def abrir_activo(self, paquete: bytes, hardware_id_actual: str, fecha_caducidad_original: float) -> bytes:
        if time.time() > fecha_caducidad_original:
            raise ValueError("APOPTOSIS INDUCIDA: Tiempo de vida expirado.")

        nonce = paquete[:12]
        datos_cifrados = paquete[12:]
        metadatos_esperados = f"{hardware_id_actual}|{fecha_caducidad_original}".encode()

        try:
            return self.aesgcm.decrypt(nonce, datos_cifrados, metadatos_esperados)
        except Exception:
            raise ValueError("COLAPSO ENTRÓPICO: Identidad de hardware incorrecta o paquete corrupto.")
