
import pytest

from servidor.firmas_servidor import (
    preparar_firmas_servidor,
    firmar_respuesta_registro
)

from victima.cliente import verificar_registro_firmado


def test_firma_correcta(tmp_path):
    # Preparar las claves del servidor.
    claves = preparar_firmas_servidor(tmp_path)

    # Simular una respuesta del servidor.
    respuesta = {
        "tipo": "registro_ok",
        "idV": "victima-prueba",
        "pkS": "CLAVE_RSA_PRUEBA"
    }

    # Firmar la respuesta.
    respuesta_firmada = firmar_respuesta_registro(
        respuesta,
        claves["privada"]
    )

    # Comprobar que la firma sea valida.
    assert verificar_registro_firmado(
        respuesta_firmada,
        claves["publica"]
    )


def test_detectar_modificacion(tmp_path):
    claves = preparar_firmas_servidor(tmp_path)

    respuesta = {
        "tipo": "registro_ok",
        "idV": "victima-prueba",
        "pkS": "CLAVE_ORIGINAL"
    }

    respuesta_firmada = firmar_respuesta_registro(
        respuesta,
        claves["privada"]
    )

    # Simulamos que alguien cambia la clave RSA.
    respuesta_firmada["pkS"] = "CLAVE_FALSA"

    # La firma debe ser rechazada.
    with pytest.raises(ValueError):
        verificar_registro_firmado(
            respuesta_firmada,
            claves["publica"]
        )
