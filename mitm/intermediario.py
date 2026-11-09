
"""
Demostracion defensiva MITM mediante TCP local.

Escenarios:
1. Registro legitimo aceptado.
2. Sustitucion de clave RSA detectada mediante Ed25519.

Solo utiliza mensajes sinteticos y 127.0.0.1.
No modifica archivos ni intercepta trafico externo.
"""

import base64
import json
import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from compartido.firmas import generar_claves_firma
from servidor.firmas_servidor import firmar_respuesta_registro
from victima.cliente import verificar_registro_firmado


ID_VICTIMA = "victima-laboratorio"


def generar_clave_publica():
    """Genera una clave RSA publica ficticia en Base64."""

    privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    publica_pem = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return base64.b64encode(publica_pem).decode("ascii")


def enviar_json(conexion, mensaje):
    """Envia un mensaje JSON terminado en salto de linea."""

    datos = (
        json.dumps(mensaje, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    conexion.sendall(datos)


def recibir_json(conexion):
    """Recibe un mensaje JSON desde la conexion TCP."""

    datos = bytearray()

    while True:
        fragmento = conexion.recv(1)

        if not fragmento:
            raise ConnectionError("Conexion cerrada")

        if fragmento == b"\n":
            break

        datos.extend(fragmento)

        if len(datos) > 65536:
            raise ValueError("Mensaje demasiado grande")

    return json.loads(datos.decode("utf-8"))


def ejecutar_escenario(modificar_clave):
    """
    Ejecuta una comunicacion TCP local.

    El servidor genera una respuesta firmada.
    El intermediario de laboratorio puede modificar
    la clave RSA antes de entregarla al receptor.
    """

    privada_firma, publica_firma = generar_claves_firma()

    clave_legitima = generar_clave_publica()

    respuesta = {
        "tipo": "registro_ok",
        "idV": ID_VICTIMA,
        "pkS": clave_legitima
    }

    respuesta_firmada = firmar_respuesta_registro(
        respuesta,
        privada_firma
    )

    errores = []

    # Crear un servidor local en puerto temporal.
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as escucha:

        escucha.bind(("127.0.0.1", 0))
        escucha.listen(1)
        escucha.settimeout(5)

        puerto = escucha.getsockname()[1]

        def servidor_local():
            try:
                conexion, _ = escucha.accept()

                with conexion:
                    conexion.settimeout(5)

                    mensaje = dict(respuesta_firmada)

                    if modificar_clave:
                        # El intermediario sustituye la clave
                        # pero no puede reproducir la firma.
                        mensaje["pkS"] = generar_clave_publica()

                    enviar_json(conexion, mensaje)

            except Exception as error:
                errores.append(error)

        hilo = threading.Thread(
            target=servidor_local,
            daemon=True
        )

        hilo.start()

        try:
            with socket.create_connection(
                ("127.0.0.1", puerto),
                timeout=5
            ) as conexion:

                conexion.settimeout(5)

                mensaje_recibido = recibir_json(conexion)

                try:
                    verificar_registro_firmado(
                        mensaje_recibido,
                        publica_firma
                    )

                    aceptado = True

                except ValueError:
                    aceptado = False

        finally:
            hilo.join(timeout=5)

        if hilo.is_alive():
            raise RuntimeError(
                "El servidor de prueba no termino"
            )

        if errores:
            raise RuntimeError(
                f"Error en servidor local: {errores[0]}"
            )

    return aceptado


def main():
    print("=== DEMOSTRACION MITM TCP ===")

    print("\n[1] Registro legitimo")

    legitimo_aceptado = ejecutar_escenario(
        modificar_clave=False
    )

    print(
        "ACEPTADO" if legitimo_aceptado
        else "RECHAZADO"
    )

    print("\n[2] Sustitucion de clave publica")

    clave_sustituida_aceptada = ejecutar_escenario(
        modificar_clave=True
    )

    clave_sustituida_rechazada = (
        not clave_sustituida_aceptada
    )

    print(
        "ATAQUE DETECTADO"
        if clave_sustituida_rechazada
        else "FALLO: clave falsa aceptada"
    )

    aprobado = (
        legitimo_aceptado
        and clave_sustituida_rechazada
    )

    resumen = {
        "registro_intacto_aceptado": legitimo_aceptado,
        "clave_sustituida_rechazada":
            clave_sustituida_rechazada,
        "estado": (
            "APROBADO" if aprobado
            else "RECHAZADO"
        )
    }

    print("\n=== RESULTADO FINAL ===")

    print(
        json.dumps(
            resumen,
            indent=2,
            ensure_ascii=False
        )
    )

    return 0 if aprobado else 1


if __name__ == "__main__":
    raise SystemExit(main())
