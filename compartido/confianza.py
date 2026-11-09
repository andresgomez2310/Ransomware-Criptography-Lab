
import base64
import binascii
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from compartido.autenticacion import verificar_registro_victima


def verificar_identidad_autorizada(
    mensaje,
    id_autorizado,
    clave_publica_confiable_pem
):
    """
    Verifica un registro de laboratorio contra
    una identidad y una clave previamente autorizadas.

    La clave confiable se proporciona por separado:
    nunca se obtiene del propio mensaje recibido.
    """

    if not isinstance(mensaje, dict):
        raise ValueError("Mensaje invalido")

    if mensaje.get("tipo") != "registro":
        raise ValueError("Tipo incorrecto")

    id_recibido = mensaje.get("idV")
    clave_b64 = mensaje.get("pkV")
    firma_b64 = mensaje.get("firmaV")

    if id_recibido != id_autorizado:
        raise ValueError("Identidad no autorizada")

    if not isinstance(clave_b64, str):
        raise ValueError("Clave publica ausente")

    if not isinstance(firma_b64, str):
        raise ValueError("Firma ausente")

    try:
        clave_recibida = base64.b64decode(
            clave_b64,
            validate=True
        )

        firma = base64.b64decode(
            firma_b64,
            validate=True
        )

        publica = serialization.load_pem_public_key(
            clave_recibida
        )

        confiable = serialization.load_pem_public_key(
            clave_publica_confiable_pem
        )

    except (ValueError, binascii.Error) as error:
        raise ValueError(
            "Material criptografico invalido"
        ) from error

    if not isinstance(publica, rsa.RSAPublicKey):
        raise ValueError("La clave recibida no es RSA")

    if not isinstance(confiable, rsa.RSAPublicKey):
        raise ValueError("La clave confiable no es RSA")

    # Comparar la representacion canonica de ambas claves.
    recibida_der = publica.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    confiable_der = confiable.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if not hmac.compare_digest(
        recibida_der,
        confiable_der
    ):
        raise ValueError(
            "La clave publica no corresponde a la autorizada"
        )

    if not verificar_registro_victima(
        publica,
        id_recibido,
        clave_b64,
        firma
    ):
        raise ValueError("Firma de identidad invalida")

    return True
