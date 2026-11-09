
import json

import json
import uuid
import base64
import socket
from compartido.autenticacion import firmar_registro_victima
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519

from compartido.protocolo import (
    enviar_mensaje,
    recibir_mensaje
)

from compartido.firmas import (
    verificar_firma,
    datos_registro_servidor
)


CARPETA_ESTADO = Path("datos_privados/victima")
ARCHIVO_IDENTIDAD = CARPETA_ESTADO / "identidad.json"
ARCHIVO_PRIVADO = CARPETA_ESTADO / "privada.pem"
ARCHIVO_PUBLICO = CARPETA_ESTADO / "publica.pem"




def verificar_registro_firmado(
    respuesta,
    clave_verificacion
):
    """
    Verifica una respuesta de registro firmada.
    clave_verificacion debe conocerse previamente.
    """

    if respuesta.get("tipo") != "registro_ok":
        raise ValueError("Respuesta de registro incorrecta")

    id_victima = respuesta.get("idV")
    clave_b64 = respuesta.get("pkS")
    firma_b64 = respuesta.get("firmaS")

    if not all(
        isinstance(valor, str) and valor
        for valor in (id_victima, clave_b64, firma_b64)
    ):
        raise ValueError("Campos de autenticacion incompletos")

    firma = base64.b64decode(
        firma_b64,
        validate=True
    )

    datos = datos_registro_servidor(
        id_victima,
        clave_b64
    )

    if not verificar_firma(
        clave_verificacion,
        datos,
        firma
    ):
        raise ValueError(
            "Firma del servidor invalida"
        )

    return True

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

    firma = firmar_registro_victima(
        identidad["clave_privada"],
        identidad["idV"],
        clave_publica_base64
    )

    return {
        "tipo": "registro",
        "idV": identidad["idV"],
        "pkV": clave_publica_base64,
        "firmaV": base64.b64encode(firma).decode("ascii")
    }


def registrar_victima(conexion, identidad):
    """
    Envia el registro de la victima y verifica
    la autenticidad de la respuesta del servidor.
    """

    # 1. Preparar el mensaje de registro
    mensaje = crear_mensaje_registro(identidad)

    # 2. Enviar mensaje al servidor
    enviar_mensaje(conexion, mensaje)

    # 3. Recibir respuesta
    respuesta = recibir_mensaje(conexion)

    # 4. Comprobar que el registro fue aceptado
    if respuesta.get("tipo") != "registro_ok":
        raise ValueError(
            "El servidor no confirmo el registro"
        )

    # 5. Verificar el identificador
    if respuesta.get("idV") != identidad["idV"]:
        raise ValueError(
            "El identificador recibido no coincide"
        )

    # 6. Comprobar que recibimos la clave publica RSA
    if not isinstance(respuesta.get("pkS"), str):
        raise ValueError(
            "Falta la clave publica del servidor"
        )

    # 7. Cargar la clave de confianza Ed25519
    clave_confiable = cargar_clave_confiable(
        CARPETA_ESTADO / "servidor_confiable.pem"
    )

    # 8. Verificar la firma antes de aceptar la clave RSA
    verificar_registro_firmado(
        respuesta,
        clave_confiable
    )

    # 9. Decodificar la clave RSA autenticada
    clave_pem = base64.b64decode(
        respuesta["pkS"],
        validate=True
    )

    # 10. Reconstruir la clave publica RSA
    clave_servidor = serialization.load_pem_public_key(
        clave_pem
    )

    if not isinstance(clave_servidor, rsa.RSAPublicKey):
        raise ValueError(
            "La clave del servidor debe ser RSA"
        )

    if clave_servidor.key_size < 2048:
        raise ValueError(
            "La clave RSA del servidor es demasiado corta"
        )

    return {
        "respuesta": respuesta,
        "clave_publica_servidor": clave_servidor
    }


def conectar_y_registrar(
    identidad,
    host="127.0.0.1",
    puerto=5000
):
    """
    Conecta la victima con el servidor
    y realiza solamente el registro.
    """

    with socket.create_connection(
        (host, puerto),
        timeout=5
    ) as conexion:

        conexion.settimeout(5)

        resultado = registrar_victima(
            conexion,
            identidad
        )

    return resultado


def cargar_clave_confiable(ruta):
    """Carga una clave publica Ed25519 confiable."""

    ruta = Path(ruta)

    if not ruta.is_file():
        raise FileNotFoundError(
            "No existe la clave publica confiable del servidor"
        )

    clave = serialization.load_pem_public_key(
        ruta.read_bytes()
    )

    if not isinstance(clave, ed25519.Ed25519PublicKey):
        raise ValueError(
            "La clave de confianza no es Ed25519"
        )

    return clave

if __name__ == "__main__":
    identidad = preparar_identidad()

    print("\n=== IDENTIDAD DE LA VICTIMA ===")
    print("ID:", identidad["idV"])
    print(
        "Longitud RSA:",
        identidad["clave_privada"].key_size
    )
    print("Clave publica y privada disponibles.")
