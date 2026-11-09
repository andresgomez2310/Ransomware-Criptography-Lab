
import json
import base64
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def validar_desafio(desafio_b64):
    """
    Comprueba que el desafio contiene
    exactamente 32 bytes aleatorios.
    """

    if not isinstance(desafio_b64, str):
        raise ValueError("Desafio ausente")

    try:
        datos = base64.b64decode(
            desafio_b64,
            validate=True
        )
    except (ValueError, binascii.Error) as error:
        raise ValueError("Desafio mal codificado") from error

    if len(datos) != 32:
        raise ValueError(
            "El desafio debe contener 32 bytes"
        )

    return datos



def datos_registro_victima(id_victima, clave_publica_b64):
    """
    Construye los datos canonicos que firma la victima
    durante el registro RSA-PSS.
    """

    contenido = {
        "tipo": "registro",
        "idV": id_victima,
        "pkV": clave_publica_b64
    }

    return json.dumps(
        contenido,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")




def firmar_registro_victima(
    clave_privada,
    id_victima,
    clave_publica_b64
):
    datos = datos_registro_victima(
        id_victima,
        clave_publica_b64
    )

    return clave_privada.sign(
        datos,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verificar_registro_victima(
    clave_publica,
    id_victima,
    clave_publica_b64,
    firma
):
    datos = datos_registro_victima(
        id_victima,
        clave_publica_b64
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
