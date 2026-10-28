
import json
import uuid
from pathlib import Path
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


CARPETA_ESTADO = Path("datos_privados/victima")
ARCHIVO_IDENTIDAD = CARPETA_ESTADO / "identidad.json"
ARCHIVO_PRIVADO = CARPETA_ESTADO / "privada.pem"
ARCHIVO_PUBLICO = CARPETA_ESTADO / "publica.pem"


def preparar_identidad():
    CARPETA_ESTADO.mkdir(parents=True, exist_ok=True)

    archivos = [
        ARCHIVO_IDENTIDAD,
        ARCHIVO_PRIVADO,
        ARCHIVO_PUBLICO
    ]

    existentes = [archivo.exists() for archivo in archivos]

    if all(existentes):
        print("Cargando identidad existente...")
        return cargar_identidad()

    if any(existentes):
        raise RuntimeError(
            "Estado incompleto: no se generara otra identidad."
        )

    print("Generando nueva identidad de laboratorio...")

    id_victima = str(uuid.uuid4())

    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    clave_publica = clave_privada.public_key()

    privada_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    publica_pem = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    ARCHIVO_IDENTIDAD.write_text(
        json.dumps({"idV": id_victima}, indent=2),
        encoding="utf-8"
    )

    ARCHIVO_PRIVADO.write_bytes(privada_pem)
    ARCHIVO_PUBLICO.write_bytes(publica_pem)

    # Restringe permisos en sistemas compatibles.
    try:
        ARCHIVO_PRIVADO.chmod(0o600)
    except OSError:
        pass

    print("Identidad creada correctamente.")
    return cargar_identidad()


def cargar_identidad():
    id_victima = json.loads(
        ARCHIVO_IDENTIDAD.read_text(encoding="utf-8")
    )["idV"]

    clave_privada = serialization.load_pem_private_key(
        ARCHIVO_PRIVADO.read_bytes(),
        password=None
    )

    clave_publica = serialization.load_pem_public_key(
        ARCHIVO_PUBLICO.read_bytes()
    )

    if (
        clave_privada.public_key().public_numbers()
        != clave_publica.public_numbers()
    ):
        raise ValueError("Las claves RSA no corresponden")

    return {
        "idV": id_victima,
        "clave_privada": clave_privada,
        "clave_publica": clave_publica
    }


def crear_mensaje_registro(identidad):
    clave_publica_pem = identidad[
        "clave_publica"
    ].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    clave_publica_base64 = base64.b64encode(
        clave_publica_pem
    ).decode("ascii")

    return {
        "tipo": "registro",
        "idV": identidad["idV"],
        "pkV": clave_publica_base64
    }

if __name__ == "__main__":
    identidad = preparar_identidad()

    print("\n=== IDENTIDAD DE LA VICTIMA ===")
    print("ID:", identidad["idV"])
    print(
        "Longitud RSA:",
        identidad["clave_privada"].key_size
    )
    print("Clave publica y privada disponibles.")
