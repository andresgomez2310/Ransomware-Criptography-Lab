
import os
import json
import pytest

from cryptography.exceptions import InvalidTag

from victima.cifrado import (
    derivar_clave,
    cifrar_archivo,
    descifrar_archivo
)


def test_claves_diferentes():
    semilla = os.urandom(32)

    clave_0 = derivar_clave(semilla, 0)
    clave_1 = derivar_clave(semilla, 1)

    assert len(clave_0) == 32
    assert len(clave_1) == 32
    assert clave_0 != clave_1


def test_cifrado_y_recuperacion(tmp_path):
    semilla = os.urandom(32)
    original = tmp_path / "documento.txt"
    cifrado = tmp_path / "documento.enc.json"
    recuperados = tmp_path / "recuperados"

    original.write_bytes(b"Documento de prueba")

    cifrar_archivo(
        original, cifrado, semilla, "victima-001", 0
    )

    resultado = descifrar_archivo(
        cifrado, recuperados, semilla, "victima-001"
    )

    assert resultado.read_bytes() == original.read_bytes()
    assert cifrado.exists()


def test_rechazo_de_etiqueta_alterada(tmp_path):
    semilla = os.urandom(32)
    original = tmp_path / "datos.txt"
    cifrado = tmp_path / "datos.enc.json"
    recuperados = tmp_path / "recuperados"

    original.write_bytes(b"Contenido protegido")

    cifrar_archivo(
        original, cifrado, semilla, "victima-001", 0
    )

    registro = json.loads(cifrado.read_text())
    registro["tag"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    cifrado.write_text(json.dumps(registro))

    with pytest.raises(InvalidTag):
        descifrar_archivo(
            cifrado, recuperados, semilla, "victima-001"
        )

    assert not (recuperados / "datos.txt").exists()
