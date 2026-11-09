
import base64
import json

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from servidor.almacenamiento import preparar_servidor
from servidor.servidor import procesar_registro


def preparar_mensaje(id_victima="victima-test"):
    privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pem = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "tipo": "registro",
        "idV": id_victima,
        "pkV": base64.b64encode(pem).decode("ascii")
    }


def test_identidad_servidor_persistente(tmp_path):
    primera = preparar_servidor(tmp_path)
    segunda = preparar_servidor(tmp_path)

    assert (
        primera["privada"].private_numbers()
        == segunda["privada"].private_numbers()
    )


def test_registro_correcto(tmp_path):
    identidad = preparar_servidor(tmp_path / "identidad")
    mensaje = preparar_mensaje()

    respuesta = procesar_registro(
        mensaje,
        identidad,
        tmp_path / "registros"
    )

    assert respuesta["tipo"] == "registro_ok"
    assert respuesta["idV"] == "victima-test"
    assert "pkS" in respuesta

    registros = json.loads(
        (tmp_path / "registros" / "registros.json")
        .read_text(encoding="utf-8")
    )

    assert registros["victima-test"] == mensaje["pkV"]


def test_registro_repetido(tmp_path):
    identidad = preparar_servidor(tmp_path / "identidad")
    mensaje = preparar_mensaje()

    primera = procesar_registro(
        mensaje, identidad, tmp_path / "registros"
    )
    segunda = procesar_registro(
        mensaje, identidad, tmp_path / "registros"
    )

    assert primera["idV"] == segunda["idV"]
    assert primera["pkS"] == segunda["pkS"]


def test_clave_invalida(tmp_path):
    identidad = preparar_servidor(tmp_path / "identidad")

    mensaje = {
        "tipo": "registro",
        "idV": "victima-test",
        "pkV": "NO_ES_BASE64!"
    }

    with pytest.raises(ValueError):
        procesar_registro(
            mensaje, identidad, tmp_path / "registros"
        )
