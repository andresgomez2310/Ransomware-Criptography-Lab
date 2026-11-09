
import base64
import json
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
    """Obtiene un puerto TCP disponible para las pruebas."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def arrancar_servidor(carpeta, puerto):
    """Inicia el servidor real en un proceso independiente."""

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
    """Finaliza completamente el proceso del servidor."""

    if proceso.poll() is None:
        proceso.terminate()

    try:
        proceso.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proceso.kill()
        proceso.wait()


def test_persistencia_servidor_real(tmp_path, monkeypatch):
    """
    Verifica que el servidor real conserve sus claves
    RSA y Ed25519 despues de reiniciar.

    Tambien comprueba que la identidad ficticia
    permanezca autorizada durante ambos registros.
    """

    # 1. Aislar todos los archivos del laboratorio.
    monkeypatch.chdir(tmp_path)

    carpeta_servidor = (
        tmp_path / "datos_privados" / "servidor"
    )

    carpeta_victima = (
        tmp_path / "datos_privados" / "victima"
    )

    carpeta_victima.mkdir(parents=True)

    # 2. Preparar la identidad Ed25519 del servidor.
    firmas = preparar_firmas_servidor(
        carpeta_servidor
    )

    publica_firma_primera = firmas["publica"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 3. Instalar la clave confiable en el cliente.
    ruta_confiable = (
        carpeta_victima / "servidor_confiable.pem"
    )

    ruta_confiable.write_bytes(
        publica_firma_primera
    )

    # 4. Crear una identidad RSA ficticia.
    privada_victima = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    identidad = {
        "idV": str(uuid.uuid4()),
        "clave_privada": privada_victima,
        "clave_publica": privada_victima.public_key()
    }

    # 5. Obtener la clave publica RSA de la identidad.
    publica_pem = identidad["clave_publica"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 6. Autorizar la identidad ANTES de iniciar el servidor.
    autorizaciones = {
        identidad["idV"]: base64.b64encode(
            publica_pem
        ).decode("ascii")
    }

    ruta_autorizaciones = (
        carpeta_servidor / "identidades_autorizadas.json"
    )

    ruta_autorizaciones.write_text(
        json.dumps(
            autorizaciones,
            indent=2
        ),
        encoding="utf-8"
    )

    # 7. Seleccionar un puerto disponible.
    puerto = puerto_libre()

    # 8. Primera ejecucion del servidor TCP real.
    servidor_1 = arrancar_servidor(
        tmp_path,
        puerto
    )

    try:
        resultado_1 = conectar_y_registrar(
            identidad,
            host="127.0.0.1",
            puerto=puerto
        )
    finally:
        detener_servidor(servidor_1)

    # 9. Conservar la primera clave RSA del servidor.
    clave_rsa_primera = resultado_1[
        "clave_publica_servidor"
    ].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 10. Reiniciar el servidor en un segundo proceso.
    servidor_2 = arrancar_servidor(
        tmp_path,
        puerto
    )

    try:
        resultado_2 = conectar_y_registrar(
            identidad,
            host="127.0.0.1",
            puerto=puerto
        )
    finally:
        detener_servidor(servidor_2)

    # 11. Recuperar la clave RSA del segundo inicio.
    clave_rsa_segunda = resultado_2[
        "clave_publica_servidor"
    ].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 12. Verificar que la clave RSA no cambio.
    assert clave_rsa_primera == clave_rsa_segunda

    # 13. Verificar el identificador en ambas respuestas.
    assert (
        resultado_1["respuesta"]["idV"]
        == resultado_2["respuesta"]["idV"]
        == identidad["idV"]
    )

    assert resultado_1["respuesta"]["tipo"] == "registro_ok"
    assert resultado_2["respuesta"]["tipo"] == "registro_ok"

    # 14. Verificar que Ed25519 tambien persiste.
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

    # 15. Comprobar que la autorizacion sigue guardada.
    autorizaciones_recargadas = json.loads(
        ruta_autorizaciones.read_text(
            encoding="utf-8"
        )
    )

    assert identidad["idV"] in autorizaciones_recargadas

    assert (
        autorizaciones_recargadas[identidad["idV"]]
        == autorizaciones[identidad["idV"]]
    )
