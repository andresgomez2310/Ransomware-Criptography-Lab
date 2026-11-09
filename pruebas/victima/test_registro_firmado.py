
import base64
import pytest

from compartido.firmas import (
    generar_claves_firma,
    firmar_clave,
    datos_registro_servidor
)

from victima.cliente import verificar_registro_firmado


def crear_respuesta_firmada(privada):
    respuesta = {
        "tipo": "registro_ok",
        "idV": "victima-prueba",
        "pkS": "CLAVE_RSA_FICTICIA_BASE64"
    }

    datos = datos_registro_servidor(
        respuesta["idV"],
        respuesta["pkS"]
    )

    respuesta["firmaS"] = base64.b64encode(
        firmar_clave(privada, datos)
    ).decode("ascii")

    return respuesta


def test_registro_firmado_valido():
    privada, publica = generar_claves_firma()

    respuesta = crear_respuesta_firmada(privada)

    assert verificar_registro_firmado(
        respuesta, publica
    )


def test_registro_modificado():
    privada, publica = generar_claves_firma()

    respuesta = crear_respuesta_firmada(privada)

    respuesta["pkS"] = "CLAVE_SUSTITUIDA"

    with pytest.raises(ValueError):
        verificar_registro_firmado(
            respuesta, publica
        )


def test_firma_de_otro_servidor():
    privada_legitima, publica_legitima = generar_claves_firma()
    privada_ajena, _ = generar_claves_firma()

    respuesta = crear_respuesta_firmada(privada_ajena)

    with pytest.raises(ValueError):
        verificar_registro_firmado(
            respuesta, publica_legitima
        )
