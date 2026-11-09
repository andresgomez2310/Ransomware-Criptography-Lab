
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from servidor.firmas_servidor import preparar_firmas_servidor
from victima.cliente import conectar_y_registrar


RAIZ = Path(__file__).resolve().parents[2]


def puerto_libre():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def arrancar_servidor(carpeta, puerto):
    """Inicia el servidor real en otro proceso."""

    codigo = (
        "import sys; "
        "import servidor.servidor as s; "
        "s.PUERTO = int(sys.argv[1]); "
        "s.iniciar_servidor()"
    )

    entorno = os.environ.copy()
    entorno["PYTHONPATH"] = (
        str(RAIZ)
        + os.pathsep
        + entorno.get("PYTHONPATH", "")
    )

    proceso = subprocess.Popen(
        [sys.executable, "-u", "-c", codigo, str(puerto)],
        cwd=carpeta,
        env=entorno,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True
    )

    limite = time.monotonic() + 8

    while time.monotonic() < limite:
        if proceso.poll() is not None:
            error = proceso.stderr.read()
            raise RuntimeError(
                f"El servidor termino: {error}"
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
    raise RuntimeError("El servidor no inicio")


def detener_servidor(proceso):
    """Finaliza completamente el servidor."""

    if proceso.poll() is None:
        proceso.terminate()

    try:
        proceso.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proceso.kill()
        proceso.wait()


def test_persistencia_servidor_real(tmp_path, monkeypatch):
    # Todos los datos quedan aislados en tmp_path.
    monkeypatch.chdir(tmp_path)

    carpeta_servidor = (
        tmp_path / "datos_privados" / "servidor"
    )

    carpeta_victima = (
        tmp_path / "datos_privados" / "victima"
    )

    carpeta_victima.mkdir(parents=True)

    # Preparar la identidad Ed25519 del servidor.
    firmas = preparar_firmas_servidor(
        carpeta_servidor
    )

    publica_firma_primera = (
        firmas["publica"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Instalar la clave de confianza del laboratorio.
    (
        carpeta_victima / "servidor_confiable.pem"
    ).write_bytes(publica_firma_primera)

    # Crear una identidad RSA ficticia.
    privada_victima = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    identidad = {
        "idV": str(uuid.uuid4()),
        "clave_privada": privada_victima,
        "clave_publica": privada_victima.public_key()
    }

    puerto = puerto_libre()

    # Primera ejecución real.
    servidor_1 = arrancar_servidor(
        tmp_path, puerto
    )

    try:
        resultado_1 = conectar_y_registrar(
            identidad,
            host="127.0.0.1",
            puerto=puerto
        )
    finally:
        detener_servidor(servidor_1)

    clave_rsa_primera = resultado_1[
        "clave_publica_servidor"
    ].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Segundo arranque: otro proceso real.
    servidor_2 = arrancar_servidor(
        tmp_path, puerto
    )

    try:
        resultado_2 = conectar_y_registrar(
            identidad,
            host="127.0.0.1",
            puerto=puerto
        )
    finally:
        detener_servidor(servidor_2)

    clave_rsa_segunda = resultado_2[
        "clave_publica_servidor"
    ].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Confirmar que la identidad RSA no cambió.
    assert clave_rsa_primera == clave_rsa_segunda

    # Confirmar que el identificador se conserva.
    assert (
        resultado_1["respuesta"]["idV"]
        == resultado_2["respuesta"]["idV"]
        == identidad["idV"]
    )

    # Confirmar que la identidad Ed25519 persiste.
    firmas_recargadas = preparar_firmas_servidor(
        carpeta_servidor
    )

    publica_firma_segunda = (
        firmas_recargadas["publica"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    assert (
        publica_firma_primera
        == publica_firma_segunda
    )
