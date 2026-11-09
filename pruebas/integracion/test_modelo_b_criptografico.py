
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding
)
from cryptography.hazmat.primitives import hashes

from material_profesor.generador_semillas import generar_semilla_maestra
from victima.cifrado import derivar_clave

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import os


def test_modelo_b_criptografico():
    # 1. Crear identidad RSA de laboratorio
    privada_servidor = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    publica_servidor = privada_servidor.public_key()

    # 2. Utilizar el generador ORIGINAL del profesor
    semilla = generar_semilla_maestra()

    assert len(semilla) == 32

    # 3. Proteger la semilla con RSA-OAEP
    semilla_protegida = publica_servidor.encrypt(
        semilla,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    assert semilla_protegida != semilla

    # 4. Recuperarla con la clave privada RSA
    semilla_recuperada = privada_servidor.decrypt(
        semilla_protegida,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    assert semilla_recuperada == semilla

    # 5. Derivar una clave AES utilizando HMAC
    clave_aes = derivar_clave(
        semilla_recuperada,
        contador=0
    )

    assert len(clave_aes) == 32

    # 6. Proteger un mensaje ficticio en memoria
    contenido = b"Documento ficticio de laboratorio"

    nonce = os.urandom(12)
    aad = b"laboratorio-modelo-b"

    aes = AESGCM(clave_aes)

    cifrado = aes.encrypt(
        nonce,
        contenido,
        aad
    )

    # 7. Comprobar la recuperación exacta
    recuperado = aes.decrypt(
        nonce,
        cifrado,
        aad
    )

    assert recuperado == contenido
