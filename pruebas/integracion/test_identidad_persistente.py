
import base64

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from compartido.autenticacion import firmar_registro_victima

from servidor.almacenamiento import preparar_servidor
from servidor.servidor import procesar_registro


def crear_registro(id_victima, clave_privada):
    """
    Crea un mensaje de registro con firma RSA-PSS.
    """

    # Obtener la clave publica RSA
    publica_pem = clave_privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Convertir la clave publica a Base64
    clave_b64 = base64.b64encode(
        publica_pem
    ).decode("ascii")

    # Firmar el registro con la misma clave privada
    firma = firmar_registro_victima(
        clave_privada,
        id_victima,
        clave_b64
    )

    # Construir el mensaje completo
    return {
        "tipo": "registro",
        "idV": id_victima,
        "pkV": clave_b64,
        "firmaV": base64.b64encode(
            firma
        ).decode("ascii")
    }


def test_proteger_identidad_registrada(tmp_path):
    """
    Comprueba que el servidor conserva una identidad
    registrada y rechaza una clave RSA diferente.
    """

    # 1. Preparar el almacenamiento real del servidor
    carpeta_servidor = tmp_path / "servidor"

    identidad_servidor = preparar_servidor(
        carpeta_servidor
    )

    # 2. Generar la primera identidad RSA
    primera_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    mensaje_original = crear_registro(
        "victima-laboratorio",
        primera_privada
    )

    # 3. Registrar la identidad por primera vez
    respuesta = procesar_registro(
        mensaje_original,
        identidad_servidor,
        carpeta_registros=carpeta_servidor
    )

    assert respuesta["tipo"] == "registro_ok"
    assert respuesta["idV"] == "victima-laboratorio"
    assert respuesta["firmaS"]

    # 4. Repetir el registro con la misma identidad
    respuesta_repetida = procesar_registro(
        mensaje_original,
        identidad_servidor,
        carpeta_registros=carpeta_servidor
    )

    assert respuesta_repetida["tipo"] == "registro_ok"

    # 5. Generar una segunda clave RSA diferente
    segunda_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Utilizar el mismo identificador con otra clave
    mensaje_modificado = crear_registro(
        "victima-laboratorio",
        segunda_privada
    )

    # 6. El servidor debe rechazar la sustitucion
    with pytest.raises(
        ValueError,
        match="El identificador ya tiene otra clave publica"
    ):
        procesar_registro(
            mensaje_modificado,
            identidad_servidor,
            carpeta_registros=carpeta_servidor
        )

    # 7. La identidad original debe seguir funcionando
    respuesta_final = procesar_registro(
        mensaje_original,
        identidad_servidor,
        carpeta_registros=carpeta_servidor
    )

    assert respuesta_final["tipo"] == "registro_ok"
    assert respuesta_final["idV"] == "victima-laboratorio"
    assert respuesta_final["pkS"] == respuesta["pkS"]
