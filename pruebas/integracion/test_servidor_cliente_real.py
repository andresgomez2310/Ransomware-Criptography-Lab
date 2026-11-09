
import base64
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ed25519
)

from servidor.firmas_servidor import preparar_firmas_servidor
from victima.cliente import conectar_y_registrar
import victima.cliente as cliente


RAIZ = Path(__file__).resolve().parents[2]


def crear_identidad_prueba():
    privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    return {
        "idV": str(uuid.uuid4()),
        "clave_privada": privada,
        "clave_publica": privada.public_key()
    }


def conseguir_puerto_libre():
    with socket.socket() as conexion:
        conexion.bind(("127.0.0.1", 0))
        return conexion.getsockname()[1]


@pytest.fixture
def servidor_real(tmp_path, monkeypatch):
    # Aislar los archivos del laboratorio.
    monkeypatch.chdir(tmp_path)

    carpeta_servidor = (
        tmp_path / "datos_privados" / "servidor"
    )

    # Crear una identidad Ed25519 persistente.
    claves = preparar_firmas_servidor(
        carpeta_servidor
    )

    carpeta_victima = (
        tmp_path / "datos_privados" / "victima"
    )
    carpeta_victima.mkdir(parents=True)

    ruta_confiable = (
        carpeta_victima / "servidor_confiable.pem"
    )

    ruta_confiable.write_bytes(
        claves["publica"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # NUEVO: crear una identidad RSA de laboratorio
    # y autorizarla antes de arrancar el servidor.
    identidad_autorizada = crear_identidad_prueba()

    publica_pem = identidad_autorizada[
        "clave_publica"
    ].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    autorizaciones = {
        identidad_autorizada["idV"]: base64.b64encode(
            publica_pem
        ).decode("ascii")
    }

    ruta_autorizaciones = (
        carpeta_servidor / "identidades_autorizadas.json"
    )

    ruta_autorizaciones.write_text(
        json.dumps(autorizaciones, indent=2),
        encoding="utf-8"
    )

    # Arrancar el modulo REAL del servidor,
    # cambiando solo el puerto de la prueba.
    puerto = conseguir_puerto_libre()

    codigo = (
        "import sys; "
        "import servidor.servidor as s; "
        "s.PUERTO = int(sys.argv[1]); "
        "s.iniciar_servidor()"
    )

    entorno = os.environ.copy()
    entorno["PYTHONPATH"] = str(RAIZ) + os.pathsep + (
        entorno.get("PYTHONPATH", "")
    )

    proceso = subprocess.Popen(
        [sys.executable, "-u", "-c", codigo, str(puerto)],
        cwd=tmp_path,
        env=entorno,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        # Esperar hasta que el servidor escuche.
        limite = time.monotonic() + 8

        while time.monotonic() < limite:
            if proceso.poll() is not None:
                pytest.fail(
                    "El servidor termino inesperadamente: "
                    + proceso.stderr.read()
                )

            try:
                with socket.create_connection(
                    ("127.0.0.1", puerto),
                    timeout=0.2
                ):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("El servidor no inicio a tiempo")

        yield {
            "puerto": puerto,
            "ruta_confiable": ruta_confiable,
            "identidad": identidad_autorizada
        }

    finally:
        proceso.terminate()
        try:
            proceso.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proceso.kill()
            proceso.wait()


def test_registro_real_autenticado(servidor_real):
    # Utilizar la identidad previamente autorizada.
    identidad = servidor_real["identidad"]

    resultado = conectar_y_registrar(
        identidad,
        host="127.0.0.1",
        puerto=servidor_real["puerto"]
    )

    assert resultado["respuesta"]["tipo"] == "registro_ok"
    assert resultado["respuesta"]["idV"] == identidad["idV"]
    assert resultado["respuesta"]["firmaS"]

    assert isinstance(
        resultado["clave_publica_servidor"],
        rsa.RSAPublicKey
    )


def test_rechazo_servidor_no_confiable(
    servidor_real,
    monkeypatch
):
    # Utilizar una identidad autorizada para que
    # la prueba llegue a verificar la firma Ed25519.
    identidad = servidor_real["identidad"]

    # Crear una clave de confianza DIFERENTE.
    clave_ajena = ed25519.Ed25519PrivateKey.generate()

    ruta_incorrecta = Path(
        "clave_no_confiable.pem"
    )

    ruta_incorrecta.write_bytes(
        clave_ajena.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # El servidor sigue siendo el real.
    # Cambiamos solo la confianza del cliente de prueba.
    cargar_original = cliente.cargar_clave_confiable

    def cargar_clave_incorrecta(ruta):
        return cargar_original(ruta_incorrecta)

    monkeypatch.setattr(
        cliente,
        "cargar_clave_confiable",
        cargar_clave_incorrecta
    )

    with pytest.raises(ValueError, match="Firma"):
        conectar_y_registrar(
            identidad,
            host="127.0.0.1",
            puerto=servidor_real["puerto"]
        )


def test_rechazo_identidad_no_autorizada(
    servidor_real
):
    """
    Comprueba que el servidor TCP real rechaza
    una identidad RSA que no figura en la lista
    de identidades previamente autorizadas.
    """

    # Crear una identidad distinta de la autorizada.
    identidad_desconocida = crear_identidad_prueba()

    assert (
        identidad_desconocida["idV"]
        != servidor_real["identidad"]["idV"]
    )

    # El servidor debe rechazar el registro.
    with pytest.raises(
        ValueError,
        match="El servidor no confirmo el registro"
    ):
        conectar_y_registrar(
            identidad_desconocida,
            host="127.0.0.1",
            puerto=servidor_real["puerto"]
        )


def test_rechazo_suplantacion_clave_rsa(servidor_real):
    """
    Una identidad con ID autorizado, pero con otra
    clave RSA, no debe poder registrarse.
    """

    identidad_autorizada = servidor_real["identidad"]
    identidad_falsa = crear_identidad_prueba()

    # Utilizar el identificador de la identidad legitima,
    # pero conservar la clave privada RSA del tercero.
    identidad_falsa["idV"] = identidad_autorizada["idV"]

    assert (
        identidad_falsa["clave_publica"].public_numbers()
        != identidad_autorizada["clave_publica"].public_numbers()
    )

    with pytest.raises(
        ValueError,
        match="El servidor no confirmo el registro"
    ):
        conectar_y_registrar(
            identidad_falsa,
            host="127.0.0.1",
            puerto=servidor_real["puerto"]
        )


def test_rechazo_sin_lista_autorizaciones(servidor_real):
    """
    El servidor TCP debe rechazar nuevas solicitudes
    si desaparece el archivo de autorizaciones.
    """

    ruta_autorizaciones = (
        servidor_real["ruta_confiable"]
        .parent
        .parent
        / "servidor"
        / "identidades_autorizadas.json"
    )

    assert ruta_autorizaciones.exists()

    # Eliminar exclusivamente el archivo temporal
    # creado por la fixture de prueba.
    ruta_autorizaciones.unlink()

    with pytest.raises(
        ValueError,
        match="El servidor no confirmo el registro"
    ):
        conectar_y_registrar(
            servidor_real["identidad"],
            host="127.0.0.1",
            puerto=servidor_real["puerto"]
        )

