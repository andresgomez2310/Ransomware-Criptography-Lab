
import hashlib
import os
import subprocess
import sys
from pathlib import Path


RAIZ = Path(__file__).resolve().parents[2]


def ejecutar_proceso(codigo, *argumentos):
    """Ejecuta codigo en un proceso Python independiente."""

    resultado = subprocess.run(
        [sys.executable, "-c", codigo, *map(str, argumentos)],
        cwd=RAIZ,
        capture_output=True,
        text=True,
        timeout=15,
        check=True
    )

    return resultado


def test_recuperacion_tras_reinicio(tmp_path):
    # Archivos creados exclusivamente por pytest.
    original = tmp_path / "documento.txt"
    cifrado = tmp_path / "documento.enc.json"
    recuperados = tmp_path / "recuperados"
    archivo_semilla = tmp_path / "semilla_prueba.bin"

    original.write_bytes(b"Archivo ficticio de laboratorio")

    # La prueba conserva su propia semilla.
    archivo_semilla.write_bytes(os.urandom(32))

    # Primer proceso: cifrado de un archivo explicito.
    codigo_cifrado = """
import sys
from pathlib import Path
from victima.cifrado import cifrar_archivo

original, cifrado, ruta_semilla = sys.argv[1:4]
semilla = Path(ruta_semilla).read_bytes()

cifrar_archivo(
    original,
    cifrado,
    semilla,
    "victima-laboratorio",
    0
)
"""

    ejecutar_proceso(
        codigo_cifrado,
        original,
        cifrado,
        archivo_semilla
    )

    assert cifrado.exists()

    # El primer proceso ya termino.
    # Ahora ejecutamos un segundo proceso independiente.
    codigo_recuperacion = """
import sys
from pathlib import Path
from victima.cifrado import descifrar_archivo

cifrado, destino, ruta_semilla = sys.argv[1:4]
semilla = Path(ruta_semilla).read_bytes()

descifrar_archivo(
    cifrado,
    destino,
    semilla,
    "victima-laboratorio"
)
"""

    ejecutar_proceso(
        codigo_recuperacion,
        cifrado,
        recuperados,
        archivo_semilla
    )

    recuperado = recuperados / "documento.txt"

    assert recuperado.exists()

    hash_original = hashlib.sha256(
        original.read_bytes()
    ).hexdigest()

    hash_recuperado = hashlib.sha256(
        recuperado.read_bytes()
    ).hexdigest()

    assert hash_original == hash_recuperado
    assert original.read_bytes() == recuperado.read_bytes()
