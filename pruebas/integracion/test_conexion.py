
import base64
import socket
import threading

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from compartido.protocolo import (
    enviar_mensaje,
    recibir_mensaje
)

from victima.cliente import conectar_y_registrar


def test_conexion_rechaza_registro_sin_firma():
    """
    Comprueba que el cliente real rechaza una
    respuesta TCP que no contiene firma Ed25519.
    """

    # 1. Crear identidad RSA de laboratorio
    privada_victima = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    identidad = {
        "idV": "victima-test",
        "clave_privada": privada_victima,
        "clave_publica": privada_victima.public_key()
    }

    # 2. Generar una clave RSA para la respuesta
    privada_servidor = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    publica_servidor = privada_servidor.public_key()

    pem = publica_servidor.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    errores = []

    # 3. Crear un servidor TCP local de prueba
    escucha = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    escucha.bind(("127.0.0.1", 0))
    escucha.listen(1)
    escucha.settimeout(5)

    puerto = escucha.getsockname()[1]

    def servidor_simulado():
        try:
            conexion, _ = escucha.accept()

            with conexion:
                conexion.settimeout(5)

                # Recibir registro del cliente real
                mensaje = recibir_mensaje(conexion)

                assert mensaje["tipo"] == "registro"
                assert mensaje["idV"] == "victima-test"

                # Responder deliberadamente SIN firmaS
                respuesta = {
                    "tipo": "registro_ok",
                    "idV": mensaje["idV"],
                    "pkS": base64.b64encode(
                        pem
                    ).decode("ascii")
                }

                enviar_mensaje(conexion, respuesta)

        except Exception as error:
            errores.append(error)

        finally:
            escucha.close()

    # 4. Iniciar el servidor local en otro hilo
    hilo = threading.Thread(
        target=servidor_simulado
    )

    hilo.start()

    try:
        # 5. El cliente real DEBE rechazar
        # la respuesta porque falta firmaS.
        with pytest.raises(
            ValueError,
            match="Campos de autenticacion incompletos"
        ):
            conectar_y_registrar(
                identidad,
                host="127.0.0.1",
                puerto=puerto
            )

    finally:
        hilo.join(timeout=6)

        if hilo.is_alive():
            escucha.close()
            hilo.join(timeout=2)

    # 6. Comprobar que el servidor de prueba
    # no produjo errores inesperados
    assert not hilo.is_alive(), (
        "El hilo del servidor no termino"
    )

    assert not errores, (
        f"Errores del servidor de prueba: {errores}"
    )
