
import socket
import pytest

from compartido.protocolo import (
    enviar_mensaje,
    recibir_mensaje
)


def test_envio_y_recepcion():
    cliente, servidor = socket.socketpair()

    try:
        mensaje_original = {
            "tipo": "registro",
            "idV": "victima-001",
            "pkV": "CLAVE_PUBLICA_PRUEBA"
        }

        enviar_mensaje(cliente, mensaje_original)

        mensaje_recibido = recibir_mensaje(servidor)

        assert mensaje_recibido == mensaje_original

    finally:
        cliente.close()
        servidor.close()


def test_mensaje_sin_tipo():
    cliente, servidor = socket.socketpair()

    try:
        mensaje_invalido = {
            "idV": "victima-001"
        }

        with pytest.raises(ValueError):
            enviar_mensaje(cliente, mensaje_invalido)

    finally:
        cliente.close()
        servidor.close()


def test_mensaje_json_invalido():
    cliente, servidor = socket.socketpair()

    try:
        cliente.sendall(b"esto no es JSON\n")

        with pytest.raises(ValueError):
            recibir_mensaje(servidor)

    finally:
        cliente.close()
        servidor.close()
