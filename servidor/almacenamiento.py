
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


CARPETA = Path("datos_privados/servidor")


def preparar_servidor(carpeta=CARPETA):
    """Crea o carga la identidad RSA del servidor."""

    carpeta = Path(carpeta)
    carpeta.mkdir(parents=True, exist_ok=True)

    privada = carpeta / "privada.pem"
    publica = carpeta / "publica.pem"

    if privada.exists() and publica.exists():
        clave_privada = serialization.load_pem_private_key(
            privada.read_bytes(),
            password=None
        )

        clave_publica = serialization.load_pem_public_key(
            publica.read_bytes()
        )

        if (
            clave_privada.public_key().public_numbers()
            != clave_publica.public_numbers()
        ):
            raise ValueError("Las claves RSA no coinciden")

    elif privada.exists() or publica.exists():
        raise RuntimeError("Identidad del servidor incompleta")

    else:
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        clave_publica = clave_privada.public_key()

        privada.write_bytes(
            clave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

        publica.write_bytes(
            clave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        privada.chmod(0o600)

    return {
        "privada": clave_privada,
        "publica": clave_publica
    }


def registrar_identidad(id_victima, clave_publica_b64,
                        carpeta=CARPETA):
    """Guarda una clave publica asociada a una identidad."""

    carpeta = Path(carpeta)
    carpeta.mkdir(parents=True, exist_ok=True)

    archivo = carpeta / "registros.json"

    if archivo.exists():
        registros = json.loads(
            archivo.read_text(encoding="utf-8")
        )
    else:
        registros = {}

    anterior = registros.get(id_victima)

    if anterior is not None and anterior != clave_publica_b64:
        raise ValueError(
            "El identificador ya tiene otra clave publica"
        )

    registros[id_victima] = clave_publica_b64

    archivo.write_text(
        json.dumps(registros, indent=2),
        encoding="utf-8"
    )

    return True
