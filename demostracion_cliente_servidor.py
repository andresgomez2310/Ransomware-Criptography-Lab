
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from servidor.firmas_servidor import preparar_firmas_servidor


RAIZ = Path(__file__).resolve().parent


def puerto_libre():
    with socket.socket() as conexion:
        conexion.bind(("127.0.0.1", 0))
        return conexion.getsockname()[1]


def entorno_python():
    entorno = os.environ.copy()
    anterior = entorno.get("PYTHONPATH", "")
    entorno["PYTHONPATH"] = (
        str(RAIZ) + (os.pathsep + anterior if anterior else "")
    )
    return entorno


def iniciar_servidor(carpeta, puerto):
    codigo = """
from servidor import servidor
servidor.HOST = "127.0.0.1"
servidor.PUERTO = int(__import__("sys").argv[1])
servidor.iniciar_servidor()
"""

    proceso = subprocess.Popen(
        [sys.executable, "-u", "-c", codigo, str(puerto)],
        cwd=carpeta,
        env=entorno_python(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True
    )

    limite = time.monotonic() + 8

    while time.monotonic() < limite:
        if proceso.poll() is not None:
            error = proceso.stderr.read()
            raise RuntimeError(
                f"El servidor no inicio: {error}"
            )

        try:
            with socket.create_connection(
                ("127.0.0.1", puerto),
                timeout=0.2
            ):
                return proceso
        except OSError:
            time.sleep(0.1)

    detener_servidor(proceso)
    raise TimeoutError("Servidor no disponible")


def detener_servidor(proceso):
    if proceso.poll() is None:
        proceso.terminate()
        try:
            proceso.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proceso.kill()
            proceso.wait(timeout=3)

    if proceso.stderr:
        proceso.stderr.close()


def registrar_cliente(carpeta, puerto):
    codigo = """
import hashlib
import json
import sys

from cryptography.hazmat.primitives import serialization
from victima.cliente import (
    preparar_identidad,
    conectar_y_registrar
)

identidad = preparar_identidad()

resultado = conectar_y_registrar(
    identidad,
    host="127.0.0.1",
    puerto=int(sys.argv[1])
)

clave = resultado["clave_publica_servidor"]

pem = clave.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("RESULTADO_JSON:" + json.dumps({
    "idV": identidad["idV"],
    "registro": resultado["respuesta"]["tipo"],
    "rsa_bits": clave.key_size,
    "huella_servidor": hashlib.sha256(pem).hexdigest()
}))
"""

    resultado = subprocess.run(
        [sys.executable, "-c", codigo, str(puerto)],
        cwd=carpeta,
        env=entorno_python(),
        capture_output=True,
        text=True,
        timeout=12
    )

    if resultado.returncode:
        raise RuntimeError(
            resultado.stderr or resultado.stdout
        )

    for linea in resultado.stdout.splitlines():
        if linea.startswith("RESULTADO_JSON:"):
            return json.loads(
                linea.removeprefix("RESULTADO_JSON:")
            )

    raise RuntimeError("No se recibio el resultado del cliente")


def main():
    print("=== INTEGRACION REAL CLIENTE-SERVIDOR ===")

    with tempfile.TemporaryDirectory(
        prefix="laboratorio_tcp_"
    ) as temporal:

        carpeta = Path(temporal)
        servidor_dir = carpeta / "datos_privados" / "servidor"
        victima_dir = carpeta / "datos_privados" / "victima"

        victima_dir.mkdir(parents=True)

        # Instalar la clave publica confiable del servidor.
        firmas = preparar_firmas_servidor(servidor_dir)

        clave_confiable = firmas["publica"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        ruta_confiable = (
            victima_dir / "servidor_confiable.pem"
        )
        ruta_confiable.write_bytes(clave_confiable)

        puerto = puerto_libre()

        # Primer inicio del servidor real.
        proceso = iniciar_servidor(carpeta, puerto)

        try:
            print("[1] Registro inicial")
            primero = registrar_cliente(carpeta, puerto)

            print("[2] Segundo registro")
            segundo = registrar_cliente(carpeta, puerto)

            assert primero["idV"] == segundo["idV"]
            assert (
                primero["huella_servidor"]
                == segundo["huella_servidor"]
            )

            # Simular confianza en otra clave Ed25519.
            print("[3] Rechazo de clave no confiable")

            clave_ajena = (
                ed25519.Ed25519PrivateKey.generate()
                .public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

            ruta_confiable.write_bytes(clave_ajena)

            rechazada = False

            try:
                registrar_cliente(carpeta, puerto)
            except RuntimeError as error:
                if "Firma del servidor invalida" in str(error):
                    rechazada = True
                else:
                    raise

            assert rechazada, (
                "El cliente acepto una clave no confiable"
            )

            ruta_confiable.write_bytes(clave_confiable)

        finally:
            detener_servidor(proceso)

        # Reiniciar el programa real del servidor.
        print("[4] Registro despues del reinicio")

        proceso = iniciar_servidor(carpeta, puerto)

        try:
            tercero = registrar_cliente(carpeta, puerto)
        finally:
            detener_servidor(proceso)

        assert primero["idV"] == tercero["idV"]
        assert (
            primero["huella_servidor"]
            == tercero["huella_servidor"]
        )

        assert tercero["registro"] == "registro_ok"
        assert tercero["rsa_bits"] >= 2048

        resultado = {
            "estado": "APROBADO",
            "registro_real_tcp": True,
            "identidad_persistente": True,
            "servidor_persistente": True,
            "clave_no_confiable_rechazada": rechazada,
            "reinicio_verificado": True
        }

        print("\n=== RESULTADO FINAL ===")
        print(json.dumps(resultado, indent=2))

        return 0


if __name__ == "__main__":
    raise SystemExit(main())
