
import base64
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
        str(RAIZ)
        + (os.pathsep + anterior if anterior else "")
    )

    return entorno


def ejecutar_cliente(carpeta, codigo, puerto=None):
    comando = [sys.executable, "-c", codigo]

    if puerto is not None:
        comando.append(str(puerto))

    resultado = subprocess.run(
        comando,
        cwd=carpeta,
        env=entorno_python(),
        capture_output=True,
        text=True,
        timeout=15,
        check=False
    )

    if resultado.returncode != 0:
        raise RuntimeError(
            resultado.stderr or resultado.stdout
        )

    for linea in resultado.stdout.splitlines():
        if linea.startswith("RESULTADO_JSON:"):
            return json.loads(
                linea.removeprefix("RESULTADO_JSON:")
            )

    raise RuntimeError(
        "No se recibio el resultado del cliente"
    )


def preparar_cliente_autorizado(carpeta, servidor_dir):
    """
    Crea la identidad RSA ficticia en el mismo
    almacenamiento que utilizara el cliente real.

    Solo exporta su identificador y clave publica.
    La clave privada nunca se entrega al servidor.
    """

    codigo = """
import base64
import json

from cryptography.hazmat.primitives import serialization
from victima.cliente import preparar_identidad

identidad = preparar_identidad()

publica_pem = identidad["clave_publica"].public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("RESULTADO_JSON:" + json.dumps({
    "idV": identidad["idV"],
    "pkV": base64.b64encode(publica_pem).decode("ascii")
}))
"""

    identidad = ejecutar_cliente(carpeta, codigo)

    servidor_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    ruta_autorizaciones = (
        servidor_dir / "identidades_autorizadas.json"
    )

    autorizaciones = {
        identidad["idV"]: identidad["pkV"]
    }

    ruta_autorizaciones.write_text(
        json.dumps(
            autorizaciones,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    return identidad["idV"], ruta_autorizaciones


def iniciar_servidor(carpeta, puerto):
    """
    Inicia el servidor TCP real en un proceso separado.
    """

    codigo = """
from servidor import servidor
import sys

servidor.HOST = "127.0.0.1"
servidor.PUERTO = int(sys.argv[1])
servidor.iniciar_servidor()
"""

    proceso = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-c",
            codigo,
            str(puerto)
        ],
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

    raise TimeoutError(
        "El servidor TCP no estuvo disponible"
    )


def detener_servidor(proceso):
    if proceso.poll() is None:
        proceso.terminate()

        try:
            proceso.wait(timeout=5)

        except subprocess.TimeoutExpired:
            proceso.kill()
            proceso.wait(timeout=5)

    if proceso.stderr:
        proceso.stderr.close()


def registrar_cliente(carpeta, puerto):
    """
    Ejecuta el cliente autentico en otro proceso.
    """

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
    "huella_servidor": hashlib.sha256(
        pem
    ).hexdigest()
}))
"""

    return ejecutar_cliente(
        carpeta,
        codigo,
        puerto
    )


def main():
    print("=== INTEGRACION REAL CLIENTE-SERVIDOR ===")

    with tempfile.TemporaryDirectory(
        prefix="laboratorio_tcp_"
    ) as temporal:

        carpeta = Path(temporal)

        servidor_dir = (
            carpeta / "datos_privados" / "servidor"
        )

        victima_dir = (
            carpeta / "datos_privados" / "victima"
        )

        victima_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        # 1. Crear confianza previa en Ed25519.
        firmas = preparar_firmas_servidor(
            servidor_dir
        )

        clave_confiable = (
            firmas["publica"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        ruta_confiable = (
            victima_dir / "servidor_confiable.pem"
        )

        ruta_confiable.write_bytes(
            clave_confiable
        )

        # 2. Preparar la autorizacion ANTES del servidor.
        print("[1] Autorizacion previa de identidad")

        id_autorizado, ruta_autorizaciones = (
            preparar_cliente_autorizado(
                carpeta,
                servidor_dir
            )
        )

        assert ruta_autorizaciones.is_file()

        # 3. Arrancar el servidor real.
        puerto = puerto_libre()

        proceso = iniciar_servidor(
            carpeta,
            puerto
        )

        try:
            print("[2] Primer registro TCP")

            primero = registrar_cliente(
                carpeta,
                puerto
            )

            assert primero["idV"] == id_autorizado
            assert primero["registro"] == "registro_ok"

            print("[3] Segundo registro TCP")

            segundo = registrar_cliente(
                carpeta,
                puerto
            )

            assert segundo["idV"] == id_autorizado

            assert (
                primero["huella_servidor"]
                == segundo["huella_servidor"]
            )

            # 4. Rechazar una clave Ed25519 ajena.
            print("[4] Rechazo de servidor no confiable")

            clave_ajena = (
                ed25519.Ed25519PrivateKey.generate()
                .public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

            ruta_confiable.write_bytes(
                clave_ajena
            )

            rechazada = False

            try:
                registrar_cliente(
                    carpeta,
                    puerto
                )

            except RuntimeError as error:
                if "Firma del servidor invalida" in str(error):
                    rechazada = True
                else:
                    raise

            assert rechazada, (
                "El cliente acepto una firma no confiable"
            )

        finally:
            ruta_confiable.write_bytes(
                clave_confiable
            )
            detener_servidor(proceso)

        # 5. Reiniciar completamente el servidor.
        print("[5] Registro despues del reinicio")

        proceso = iniciar_servidor(
            carpeta,
            puerto
        )

        try:
            tercero = registrar_cliente(
                carpeta,
                puerto
            )

        finally:
            detener_servidor(proceso)

        assert tercero["idV"] == id_autorizado
        assert tercero["registro"] == "registro_ok"
        assert tercero["rsa_bits"] >= 2048

        assert (
            primero["huella_servidor"]
            == tercero["huella_servidor"]
        )

        autorizaciones_recargadas = json.loads(
            ruta_autorizaciones.read_text(
                encoding="utf-8"
            )
        )

        assert (
            id_autorizado
            in autorizaciones_recargadas
        )

        # 6. Informe final.
        resultado = {
            "estado": "APROBADO",
            "registro_real_tcp": True,
            "autorizacion_previa": True,
            "identidad_persistente": True,
            "servidor_persistente": True,
            "clave_no_confiable_rechazada": rechazada,
            "reinicio_verificado": True,
            "claves_rsa_minimo_bits": tercero["rsa_bits"],
            "archivos_temporales": True
        }

        print("\n=== RESULTADO FINAL ===")
        print(
            json.dumps(
                resultado,
                indent=2,
                ensure_ascii=False
            )
        )

        return 0


if __name__ == "__main__":
    raise SystemExit(main())
