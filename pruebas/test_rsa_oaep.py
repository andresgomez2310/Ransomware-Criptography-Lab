
import os
import pytest

from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding
)
from cryptography.hazmat.primitives import hashes


def crear_claves():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def cifrar_mensaje(clave_publica, mensaje):
    return clave_publica.encrypt(
        mensaje,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def descifrar_mensaje(clave_privada, cifrado):
    return clave_privada.decrypt(
        cifrado,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def test_cifrado_y_descifrado_rsa():
    privada = crear_claves()
    publica = privada.public_key()

    mensaje = os.urandom(32)

    cifrado = cifrar_mensaje(publica, mensaje)
    recuperado = descifrar_mensaje(privada, cifrado)

    assert len(cifrado) == 256
    assert recuperado == mensaje


def test_cifrados_diferentes():
    privada = crear_claves()
    publica = privada.public_key()

    mensaje = b"Mensaje de prueba"

    cifrado_1 = cifrar_mensaje(publica, mensaje)
    cifrado_2 = cifrar_mensaje(publica, mensaje)

    assert cifrado_1 != cifrado_2

    assert descifrar_mensaje(privada, cifrado_1) == mensaje
    assert descifrar_mensaje(privada, cifrado_2) == mensaje


def test_clave_privada_incorrecta():
    privada_correcta = crear_claves()
    privada_incorrecta = crear_claves()

    mensaje = b"Informacion de laboratorio"

    cifrado = cifrar_mensaje(
        privada_correcta.public_key(),
        mensaje
    )

    with pytest.raises(ValueError):
        descifrar_mensaje(
            privada_incorrecta,
            cifrado
        )
