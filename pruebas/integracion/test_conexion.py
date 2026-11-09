
import base64
import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from compartido.protocolo import (
    enviar_mensaje,
    recibir_mensaje
)

from victima.cliente import conectar_y_registrar


def test_conexion_registro():
    privada_victima = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    identidad = {
        "idV": "victima-test",
        "clave_privada": privada_victima,
        "clave_publica": privada_victima.public_key()
    }

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
                mensaje = recibir_mensaje(conexion)

                assert mensaje["tipo"] == "registro"
                assert mensaje["idV"] == "victima-test"

                enviar_mensaje(conexion, {
                    "tipo": "registro_ok",
                    "idV": mensaje["idV"],
                    "pkS": base64.b64encode(
                        pem
                    ).decode("ascii")
                })

        except Exception as error:
            errores.append(error)
        finally:
            escucha.close()

    hilo = threading.Thread(
        target=servidor_simulado
    )

    hilo.start()

    try:
        resultado = conectar_y_registrar(
            identidad,
            host="127.0.0.1",
            puerto=puerto
        )
    finally:
        hilo.join(timeout=5)

    assert not hilo.is_alive()
    assert not errores

    assert resultado["respuesta"]["tipo"] == "registro_ok"
    assert resultado["respuesta"]["idV"] == "victima-test"

    assert (
        resultado["clave_publica_servidor"].public_numbers()
        == publica_servidor.public_numbers()
    )
