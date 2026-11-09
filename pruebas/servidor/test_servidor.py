
import base64

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from compartido.autenticacion import firmar_registro_victima

from servidor.almacenamiento import preparar_servidor
from servidor.servidor import procesar_registro


def preparar_mensaje(
    id_victima="victima-test",
    clave_privada=None
):
    """Crea un registro firmado con RSA-PSS."""

    if clave_privada is None:
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    # Convertir la clave publica a PEM
    publica_pem = clave_privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Convertir a Base64
    clave_b64 = base64.b64encode(
        publica_pem
    ).decode("ascii")

    # Firmar el registro con la clave privada
    firma = firmar_registro_victima(
        clave_privada,
        id_victima,
        clave_b64
    )

    return {
        "tipo": "registro",
        "idV": id_victima,
        "pkV": clave_b64,
        "firmaV": base64.b64encode(
            firma
        ).decode("ascii")
    }


def test_registro_correcto(tmp_path):
    """El servidor acepta un registro valido."""

    identidad = preparar_servidor(
        tmp_path / "identidad"
    )

    mensaje = preparar_mensaje()

    respuesta = procesar_registro(
        mensaje,
        identidad,
        tmp_path / "registros"
    )

    assert respuesta["tipo"] == "registro_ok"
    assert respuesta["idV"] == mensaje["idV"]
    assert isinstance(respuesta["pkS"], str)
    assert respuesta["pkS"]
    assert isinstance(respuesta["firmaS"], str)
    assert respuesta["firmaS"]


def test_registro_repetido(tmp_path):
    """Una identidad puede registrarse nuevamente con la misma clave."""

    identidad = preparar_servidor(
        tmp_path / "identidad"
    )

    mensaje = preparar_mensaje()

    primera = procesar_registro(
        mensaje,
        identidad,
        tmp_path / "registros"
    )

    segunda = procesar_registro(
        mensaje,
        identidad,
        tmp_path / "registros"
    )

    assert primera["tipo"] == "registro_ok"
    assert segunda["tipo"] == "registro_ok"
    assert primera["idV"] == segunda["idV"]
    assert primera["pkS"] == segunda["pkS"]


def test_registro_sin_firma_rechazado(tmp_path):
    """El servidor rechaza un registro sin firma RSA-PSS."""

    identidad = preparar_servidor(
        tmp_path / "identidad"
    )

    mensaje = preparar_mensaje()

    # Eliminar la firma deliberadamente
    del mensaje["firmaV"]

    with pytest.raises(
        ValueError,
        match="Falta firma de la victima"
    ):
        procesar_registro(
            mensaje,
            identidad,
            tmp_path / "registros"
        )


def test_registro_firma_modificada(tmp_path):
    """El servidor detecta modificaciones del registro."""

    identidad = preparar_servidor(
        tmp_path / "identidad"
    )

    mensaje = preparar_mensaje()

    # Cambiar el identificador despues de firmar
    mensaje["idV"] = "victima-falsa"

    with pytest.raises(
        ValueError,
        match="Firma de la victima invalida"
    ):
        procesar_registro(
            mensaje,
            identidad,
            tmp_path / "registros"
        )


def test_registro_clave_sustituida(tmp_path):
    """El servidor rechaza otra clave para una identidad ya registrada."""

    identidad = preparar_servidor(
        tmp_path / "identidad"
    )

    mensaje_original = preparar_mensaje(
        id_victima="victima-test"
    )

    procesar_registro(
        mensaje_original,
        identidad,
        tmp_path / "registros"
    )

    # Otra clave privada con el mismo identificador
    mensaje_nuevo = preparar_mensaje(
        id_victima="victima-test"
    )

    with pytest.raises(
        ValueError,
        match="El identificador ya tiene otra clave publica"
    ):
        procesar_registro(
            mensaje_nuevo,
            identidad,
            tmp_path / "registros"
        )
