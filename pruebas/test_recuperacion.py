
import os
import pytest

from victima.cifrado import cifrar_archivo
from victima.recuperacion import (
    calcular_sha256,
    verificar_archivos,
    recuperar_y_verificar
)


def test_hashes_iguales(tmp_path):
    archivo_1 = tmp_path / "original.txt"
    archivo_2 = tmp_path / "copia.txt"

    archivo_1.write_bytes(b"Contenido identico")
    archivo_2.write_bytes(b"Contenido identico")

    assert verificar_archivos(archivo_1, archivo_2)


def test_hashes_diferentes(tmp_path):
    archivo_1 = tmp_path / "original.txt"
    archivo_2 = tmp_path / "modificado.txt"

    archivo_1.write_bytes(b"Contenido original")
    archivo_2.write_bytes(b"Contenido cambiado")

    assert not verificar_archivos(archivo_1, archivo_2)


def test_recuperacion_completa(tmp_path):
    semilla = os.urandom(32)
    id_victima = "victima-prueba-001"

    original = tmp_path / "documento.txt"
    cifrado = tmp_path / "documento.enc.json"
    carpeta_recuperados = tmp_path / "recuperados"

    original.write_bytes(
        b"Archivo de prueba del proyecto"
    )

    cifrar_archivo(
        original,
        cifrado,
        semilla,
        id_victima,
        0
    )

    resultado = recuperar_y_verificar(
        cifrado,
        carpeta_recuperados,
        semilla,
        id_victima,
        original
    )

    assert resultado["recuperado"] is True
    assert resultado["integridad"] is True

    recuperado = (
        carpeta_recuperados / "documento.txt"
    )

    assert recuperado.read_bytes() == original.read_bytes()

    assert (
        resultado["sha256"]
        == calcular_sha256(original)
    )
