
import pytest

from compartido.firmas import (
    generar_claves_firma,
    firmar_clave,
    verificar_firma
)


def test_firma_valida():
    privada, publica = generar_claves_firma()

    datos = b"Clave publica de laboratorio"
    firma = firmar_clave(privada, datos)

    assert verificar_firma(publica, datos, firma)


def test_clave_sustituida():
    privada, publica = generar_claves_firma()

    datos_originales = b"Clave RSA legitima"
    datos_alterados = b"Clave RSA sustituida"

    firma = firmar_clave(privada, datos_originales)

    assert not verificar_firma(
        publica,
        datos_alterados,
        firma
    )


def test_firmante_incorrecto():
    privada_legitima, publica_legitima = generar_claves_firma()
    privada_ajena, _ = generar_claves_firma()

    datos = b"Mensaje de autenticacion"

    firma_falsa = firmar_clave(
        privada_ajena,
        datos
    )

    assert not verificar_firma(
        publica_legitima,
        datos,
        firma_falsa
    )
