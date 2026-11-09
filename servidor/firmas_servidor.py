
import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from compartido.firmas import (
    firmar_clave,
    datos_registro_servidor
)


def preparar_firmas_servidor(carpeta=None):
    """Genera o carga las claves Ed25519 del servidor."""

    if carpeta is None:
        carpeta = Path("datos_privados/servidor")

    carpeta = Path(carpeta)
    carpeta.mkdir(parents=True, exist_ok=True)

    ruta_privada = carpeta / "firma_privada.pem"
    ruta_publica = carpeta / "firma_publica.pem"

    # Si ambas claves existen, cargarlas
    if ruta_privada.exists() and ruta_publica.exists():

        privada = serialization.load_pem_private_key(
            ruta_privada.read_bytes(),
            password=None
        )

        publica = serialization.load_pem_public_key(
            ruta_publica.read_bytes()
        )

        if not isinstance(
            privada, ed25519.Ed25519PrivateKey
        ):
            raise ValueError("Clave privada no es Ed25519")

        if not isinstance(
            publica, ed25519.Ed25519PublicKey
        ):
            raise ValueError("Clave publica no es Ed25519")

        if (
            privada.public_key().public_bytes_raw()
            != publica.public_bytes_raw()
        ):
            raise ValueError("Las claves Ed25519 no coinciden")

    # Si solamente existe una clave, hay un problema
    elif ruta_privada.exists() or ruta_publica.exists():
        raise RuntimeError("Identidad Ed25519 incompleta")

    # Si no existen, crearlas
    else:
        privada = ed25519.Ed25519PrivateKey.generate()
        publica = privada.public_key()

        ruta_privada.write_bytes(
            privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

        ruta_publica.write_bytes(
            publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return {
        "privada": privada,
        "publica": publica
    }


def firmar_respuesta_registro(respuesta, clave_privada):
    """Agrega una firma Ed25519 a una respuesta."""

    if respuesta.get("tipo") != "registro_ok":
        raise ValueError("Tipo de respuesta incorrecto")

    datos = datos_registro_servidor(
        respuesta["idV"],
        respuesta["pkS"]
    )

    firma = firmar_clave(
        clave_privada,
        datos
    )

    respuesta_firmada = respuesta.copy()

    respuesta_firmada["firmaS"] = base64.b64encode(
        firma
    ).decode("ascii")

    return respuesta_firmada
