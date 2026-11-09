
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import json


def datos_registro_servidor(id_victima, clave_publica_b64):
    """Representacion canonica del registro autenticado."""

    mensaje = {
        "tipo": "registro_ok",
        "idV": id_victima,
        "pkS": clave_publica_b64
    }

    return json.dumps(
        mensaje,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def generar_claves_firma():
    """Genera un par de claves Ed25519."""
    privada = ed25519.Ed25519PrivateKey.generate()
    publica = privada.public_key()
    return privada, publica


def firmar_clave(clave_privada, datos):
    """Firma una clave publica serializada."""
    return clave_privada.sign(datos)


def verificar_firma(clave_publica, datos, firma):
    """Verifica la autenticidad de los datos."""

    try:
        clave_publica.verify(firma, datos)
        return True

    except InvalidSignature:
        return False
