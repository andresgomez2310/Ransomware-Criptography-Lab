
import base64
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def crear_desafio():
    """Genera un desafio aleatorio de 32 bytes."""
    return base64.b64encode(
        secrets.token_bytes(32)
    ).decode("ascii")


def preparar_datos_firma(id_victima, desafio):
    """Vincula la firma a la identidad y al desafio."""

    if not isinstance(id_victima, str) or not id_victima:
        raise ValueError("Identificador invalido")

    if not isinstance(desafio, str):
        raise ValueError("Desafio invalido")

    datos_desafio = base64.b64decode(
        desafio,
        validate=True
    )

    if len(datos_desafio) != 32:
        raise ValueError("Longitud de desafio incorrecta")

    identificador = id_victima.encode("utf-8")

    return (
        b"LAB-REGISTRO-V1"
        + len(identificador).to_bytes(4, "big")
        + identificador
        + datos_desafio
    )


def firmar_desafio(clave_privada, id_victima, desafio):
    """Firma el desafio con RSA-PSS."""

    datos = preparar_datos_firma(
        id_victima,
        desafio
    )

    firma = clave_privada.sign(
        datos,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(firma).decode("ascii")


def verificar_desafio(
    clave_publica,
    id_victima,
    desafio,
    firma_b64
):
    """Verifica la firma del desafio."""

    datos = preparar_datos_firma(
        id_victima,
        desafio
    )

    firma = base64.b64decode(
        firma_b64,
        validate=True
    )

    try:
        clave_publica.verify(
            firma,
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except InvalidSignature:
        return False


class SesionDesafio:
    """Desafio valido para una sola verificacion."""

    def __init__(self):
        self.desafio = crear_desafio()
        self.utilizado = False

    def verificar(
        self,
        clave_publica,
        id_victima,
        firma_b64
    ):
        if self.utilizado:
            raise ValueError("Desafio ya utilizado")

        # Consumir antes de comprobar la firma.
        # Una respuesta fallida tampoco puede repetirse.
        self.utilizado = True

        return verificar_desafio(
            clave_publica,
            id_victima,
            self.desafio,
            firma_b64
        )
