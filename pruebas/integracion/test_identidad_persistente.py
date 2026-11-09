
import base64
import json

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from servidor.almacenamiento import preparar_servidor
from servidor.servidor import procesar_registro


def crear_registro(id_victima, clave_privada):
    publica_pem = clave_privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "tipo": "registro",
        "idV": id_victima,
        "pkV": base64.b64encode(
            publica_pem
        ).decode("ascii")
    }


def test_proteger_identidad_registrada(tmp_path):
    # Utilizar el almacenamiento real en una carpeta temporal
    carpeta_servidor = tmp_path / "servidor"
    identidad_servidor = preparar_servidor(
        carpeta_servidor
    )

    # Primera clave RSA
    primera_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    mensaje_original = crear_registro(
        "victima-laboratorio",
        primera_privada
    )

    # Primer registro
    respuesta = procesar_registro(
        mensaje_original,
        identidad_servidor,
        carpeta_registros=carpeta_servidor
    )

    assert respuesta["tipo"] == "registro_ok"

    # Registrar nuevamente la misma identidad
    respuesta_repetida = procesar_registro(
        mensaje_original,
        identidad_servidor,
        carpeta_registros=carpeta_servidor
    )

    assert respuesta_repetida["tipo"] == "registro_ok"

    # Crear otra clave RSA para el mismo identificador
    segunda_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    mensaje_modificado = crear_registro(
        "victima-laboratorio",
        segunda_privada
    )

    # El sistema debe impedir que cambien
    # la clave asociada al identificador
    with pytest.raises(ValueError):
        procesar_registro(
            mensaje_modificado,
            identidad_servidor,
            carpeta_registros=carpeta_servidor
        )

    # El registro original debe seguir siendo valido
    respuesta_final = procesar_registro(
        mensaje_original,
        identidad_servidor,
        carpeta_registros=carpeta_servidor
    )

    assert respuesta_final["tipo"] == "registro_ok"
