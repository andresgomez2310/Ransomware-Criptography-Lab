
import base64
import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from compartido.protocolo import (
    enviar_mensaje,
    recibir_mensaje
)

from servidor.firmas_servidor import (
    preparar_firmas_servidor,
    firmar_respuesta_registro
)

from victima.cliente import verificar_registro_firmado


def test_registro_firmado_por_tcp(tmp_path):
    # Identidad de firma del servidor de prueba
    claves = preparar_firmas_servidor(tmp_path)

    # Crear dos extremos de una conexion local
    socket_servidor, socket_victima = socket.socketpair()

    # Crear una clave RSA ficticia para el servidor
    privada_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    publica_rsa = privada_rsa.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    respuesta = {
        "tipo": "registro_ok",
        "idV": "victima-laboratorio",
        "pkS": base64.b64encode(
            publica_rsa
        ).decode("ascii")
    }

    respuesta_firmada = firmar_respuesta_registro(
        respuesta,
        claves["privada"]
    )

    try:
        # Enviar desde otro hilo
        hilo = threading.Thread(
            target=enviar_mensaje,
            args=(socket_servidor, respuesta_firmada)
        )

        hilo.start()

        # Recibir mediante el otro extremo del socket
        recibido = recibir_mensaje(socket_victima)

        hilo.join(timeout=3)

        assert not hilo.is_alive()
        assert recibido["tipo"] == "registro_ok"
        assert recibido["idV"] == "victima-laboratorio"

        # Validar la autenticidad de la respuesta
        assert verificar_registro_firmado(
            recibido,
            claves["publica"]
        )

    finally:
        socket_servidor.close()
        socket_victima.close()
