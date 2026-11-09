
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from material_profesor.generador_semillas import generar_semilla_maestra
from victima.cifrado import cifrar_archivo, descifrar_archivo


RAIZ = Path(__file__).resolve().parent
ID_LABORATORIO = "modelo-b-recuperacion-autorizada"


def sha256(ruta):
    return hashlib.sha256(Path(ruta).read_bytes()).hexdigest()


def ejecutar_proceso(modo, carpeta):
    resultado = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), modo, str(carpeta)],
        cwd=RAIZ,
        capture_output=True,
        text=True,
        timeout=30,
        check=False
    )

    if resultado.returncode != 0:
        raise RuntimeError(
            resultado.stderr or resultado.stdout
        )


def fase_cifrado(carpeta):
    carpeta = Path(carpeta)
    originales = carpeta / "originales"
    cifrados = carpeta / "cifrados"
    respaldo = carpeta / "respaldo_propietario"

    cifrados.mkdir()
    respaldo.mkdir()

    # Una sola semilla para este incidente ficticio.
    semilla = generar_semilla_maestra()

    if len(semilla) != 32:
        raise ValueError("Longitud de semilla incorrecta")

    # Respaldo controlado por el propietario.
    # Nunca se coloca en la carpeta de cifrados.
    ruta_respaldo = respaldo / "semilla.bin"
    ruta_respaldo.write_bytes(semilla)

    for contador, ruta in enumerate(
        sorted(originales.iterdir())
    ):
        cifrar_archivo(
            ruta,
            cifrados / f"{ruta.name}.enc.json",
            semilla,
            ID_LABORATORIO,
            contador
        )

    # Al terminar este proceso, la semilla
    # deja de estar disponible en su memoria.


def fase_recuperacion(carpeta):
    carpeta = Path(carpeta)
    cifrados = carpeta / "cifrados"
    recuperados = carpeta / "recuperados"

    ruta_respaldo = (
        carpeta / "respaldo_propietario" / "semilla.bin"
    )

    if not ruta_respaldo.is_file():
        raise FileNotFoundError(
            "No existe respaldo autorizado de recuperación"
        )

    semilla = ruta_respaldo.read_bytes()

    if len(semilla) != 32:
        raise ValueError("Respaldo inválido")

    recuperados.mkdir()

    for ruta in sorted(cifrados.glob("*.enc.json")):
        descifrar_archivo(
            ruta,
            recuperados,
            semilla,
            ID_LABORATORIO
        )


def demostracion():
    archivos = {
        "documento.txt": b"Documento ficticio de laboratorio.",
        "datos.csv": b"id,valor\n1,100\n2,200\n",
        "notas.txt": b"Recuperacion autorizada."
    }

    with tempfile.TemporaryDirectory(
        prefix="recuperacion_autorizada_"
    ) as temporal:

        carpeta = Path(temporal)
        originales = carpeta / "originales"
        cifrados = carpeta / "cifrados"
        recuperados = carpeta / "recuperados"

        originales.mkdir()

        for nombre, contenido in archivos.items():
            (originales / nombre).write_bytes(contenido)

        print("[1] Cifrando copias ficticias")
        ejecutar_proceso("cifrar", carpeta)

        salidas = sorted(cifrados.glob("*.enc.json"))
        assert len(salidas) == len(archivos)

        print("[2] Primer proceso cerrado")
        assert all(ruta.is_file() for ruta in salidas)

        print("[3] Recuperando en un proceso nuevo")
        ejecutar_proceso("recuperar", carpeta)

        print("[4] Comparando archivos byte a byte")

        comparacion = {}

        for nombre in archivos:
            original = originales / nombre
            recuperado = recuperados / nombre

            comparacion[nombre] = (
                recuperado.is_file()
                and original.read_bytes() == recuperado.read_bytes()
                and sha256(original) == sha256(recuperado)
            )

        if not all(comparacion.values()):
            raise AssertionError(
                "La recuperación no fue idéntica"
            )

        resultado = {
            "estado": "APROBADO",
            "modelo": "B",
            "archivos_cifrados": len(salidas),
            "archivos_recuperados": len(comparacion),
            "procesos_independientes": 2,
            "cifrados_persistentes": True,
            "respaldo_controlado_por_propietario": True,
            "comparacion_final": "IDENTICOS",
            "archivos": comparacion,
            "alcance": (
                "Recuperación autorizada de laboratorio. "
                "No implementa el intercambio de maestra "
                "por TCP ni el evento de pago."
            )
        }

        print(json.dumps(
            resultado,
            indent=2,
            ensure_ascii=False
        ))


def main():
    if len(sys.argv) == 1:
        demostracion()
        return

    if len(sys.argv) != 3:
        raise ValueError("Argumentos incorrectos")

    modo = sys.argv[1]
    carpeta = Path(sys.argv[2])

    if modo == "cifrar":
        fase_cifrado(carpeta)
    elif modo == "recuperar":
        fase_recuperacion(carpeta)
    else:
        raise ValueError("Modo desconocido")


if __name__ == "__main__":
    main()
