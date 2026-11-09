
import hashlib
import os

from victima.cifrado import (
    cifrar_archivo,
    descifrar_archivo
)


def calcular_hash(datos):
    return hashlib.sha256(datos).hexdigest()


def test_flujo_tres_archivos(tmp_path):
    # Laboratorio: solo archivos temporales de pytest.
    originales = tmp_path / "originales"
    cifrados = tmp_path / "cifrados"
    recuperados = tmp_path / "recuperados"

    originales.mkdir()
    cifrados.mkdir()
    recuperados.mkdir()

    # Archivos ficticios creados exclusivamente para la prueba.
    archivos = {
        "documento.txt": b"Documento de prueba",
        "datos.csv": b"id,valor\n1,100\n2,200",
        "imagen.bin": bytes(range(256))
    }

    semilla_prueba = os.urandom(32)
    id_victima = "victima-laboratorio"

    for contador, (nombre, contenido) in enumerate(
        archivos.items()
    ):
        original = originales / nombre
        cifrado = cifrados / f"{nombre}.enc.json"

        original.write_bytes(contenido)

        cifrar_archivo(
            original,
            cifrado,
            semilla_prueba,
            id_victima,
            contador
        )

        assert cifrado.exists()

        resultado = descifrar_archivo(
            cifrado,
            recuperados,
            semilla_prueba,
            id_victima
        )

        assert resultado.read_bytes() == contenido

        assert calcular_hash(
            original.read_bytes()
        ) == calcular_hash(
            resultado.read_bytes()
        )

    assert len(list(cifrados.glob("*.enc.json"))) == 3
    assert len(list(recuperados.iterdir())) == 3
