
import hashlib
import os
import subprocess
import sys
from pathlib import Path


RAIZ = Path(__file__).resolve().parents[2]


def ejecutar(codigo, *argumentos):
    """Ejecuta codigo en un proceso Python independiente."""

    return subprocess.run(
        [sys.executable, "-c", codigo, *map(str, argumentos)],
        cwd=RAIZ,
        capture_output=True,
        text=True,
        timeout=20,
        check=True
    )


def calcular_hash(ruta):
    return hashlib.sha256(
        Path(ruta).read_bytes()
    ).hexdigest()


def test_recuperar_tres_archivos_tras_reinicio(tmp_path):
    carpeta_originales = tmp_path / "originales"
    carpeta_cifrados = tmp_path / "cifrados"
    carpeta_recuperados = tmp_path / "recuperados"

    carpeta_originales.mkdir()
    carpeta_cifrados.mkdir()

    # Archivos ficticios, creados exclusivamente por la prueba
    archivos = {
        "documento.txt": b"Documento ficticio de laboratorio.",
        "datos.csv": b"id,valor\n1,100\n2,200\n",
        "imagen.bin": bytes(range(256))
    }

    for nombre, contenido in archivos.items():
        (carpeta_originales / nombre).write_bytes(contenido)

    # Semilla exclusiva de esta prueba
    ruta_semilla = tmp_path / "semilla_test.bin"
    ruta_semilla.write_bytes(os.urandom(32))

    # Primer proceso: cifrar los archivos ficticios
    codigo_cifrado = """
import sys
from pathlib import Path
from victima.cifrado import cifrar_archivo

originales, cifrados, ruta_semilla = map(
    Path, sys.argv[1:4]
)

semilla = ruta_semilla.read_bytes()

for contador, ruta in enumerate(sorted(originales.iterdir())):
    cifrar_archivo(
        ruta,
        cifrados / (ruta.name + ".enc.json"),
        semilla,
        "victima-laboratorio",
        contador
    )
"""

    ejecutar(
        codigo_cifrado,
        carpeta_originales,
        carpeta_cifrados,
        ruta_semilla
    )

    assert len(list(carpeta_cifrados.iterdir())) == 3

    # Segundo proceso: recuperar con la semilla de prueba
    codigo_recuperacion = """
import sys
from pathlib import Path
from victima.cifrado import descifrar_archivo

cifrados, recuperados, ruta_semilla = map(
    Path, sys.argv[1:4]
)

semilla = ruta_semilla.read_bytes()

recuperados.mkdir(parents=True, exist_ok=True)

for ruta in sorted(cifrados.glob("*.enc.json")):
    descifrar_archivo(
        ruta,
        recuperados,
        semilla,
        "victima-laboratorio"
    )
"""

    ejecutar(
        codigo_recuperacion,
        carpeta_cifrados,
        carpeta_recuperados,
        ruta_semilla
    )

    # Comprobacion de integridad
    for nombre in archivos:
        original = carpeta_originales / nombre
        recuperado = carpeta_recuperados / nombre

        assert recuperado.exists()
        assert calcular_hash(original) == calcular_hash(recuperado)
        assert original.read_bytes() == recuperado.read_bytes()
