
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from compartido.desafios import (
    SesionDesafio,
    firmar_desafio
)


def crear_claves():
    privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    return privada, privada.public_key()


def test_desafio_valido():
    privada, publica = crear_claves()

    sesion = SesionDesafio()

    firma = firmar_desafio(
        privada,
        "victima-prueba",
        sesion.desafio
    )

    assert sesion.verificar(
        publica,
        "victima-prueba",
        firma
    )


def test_no_reutilizar_desafio():
    privada, publica = crear_claves()

    sesion = SesionDesafio()

    firma = firmar_desafio(
        privada,
        "victima-prueba",
        sesion.desafio
    )

    assert sesion.verificar(
        publica,
        "victima-prueba",
        firma
    )

    with pytest.raises(
        ValueError,
        match="Desafio ya utilizado"
    ):
        sesion.verificar(
            publica,
            "victima-prueba",
            firma
        )


def test_no_reutilizar_firma_en_otra_sesion():
    privada, publica = crear_claves()

    primera = SesionDesafio()
    segunda = SesionDesafio()

    assert primera.desafio != segunda.desafio

    firma = firmar_desafio(
        privada,
        "victima-prueba",
        primera.desafio
    )

    assert not segunda.verificar(
        publica,
        "victima-prueba",
        firma
    )


def test_rechazar_identidad_diferente():
    privada, publica = crear_claves()

    sesion = SesionDesafio()

    firma = firmar_desafio(
        privada,
        "victima-original",
        sesion.desafio
    )

    assert not sesion.verificar(
        publica,
        "victima-diferente",
        firma
    )
