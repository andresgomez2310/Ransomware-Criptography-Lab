
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from material_profesor.generador_semillas import generar_semilla_maestra
from victima.cifrado import cifrar_archivo, descifrar_archivo


ARCHIVO_SCRIPT = Path(__file__).resolve()
ID_LABORATORIO = "victima-laboratorio"


def calcular_sha256(ruta):
    return hashlib.sha256(
        Path(ruta).read_bytes()
    ).hexdigest()


def ejecutar_proceso(fase, carpeta):
    """
    Ejecuta cada fase en un proceso Python independiente.
    """
    subprocess.run(
        [
            sys.executable,
            str(ARCHIVO_SCRIPT),
            fase,
            str(carpeta)
        ],
        cwd=ARCHIVO_SCRIPT.parent,
        check=True,
        timeout=30
    )


def fase_cifrado(carpeta):
    """
    Genera una semilla con el codigo original del profesor
    y cifra exclusivamente los archivos ficticios del laboratorio.
    """

    carpeta = Path(carpeta)
    originales = carpeta / "originales"
    cifrados = carpeta / "cifrados"

    cifrados.mkdir(parents=True, exist_ok=True)

    semilla = generar_semilla_maestra()

    if len(semilla) != 32:
        raise ValueError("Semilla de longitud incorrecta")

    # Semilla temporal para la recuperacion autorizada.
    (carpeta / "semilla_laboratorio.bin").write_bytes(semilla)

    for contador, original in enumerate(
        sorted(originales.iterdir())
    ):
        if not original.is_file():
            continue

        destino = cifrados / f"{original.name}.enc.json"

        cifrar_archivo(
            original,
            destino,
            semilla,
            ID_LABORATORIO,
            contador
        )

        print(f"CIFRADO: {original.name}")


def fase_recuperacion(carpeta):
    """
    Recupera los archivos de demostracion
    en un segundo proceso independiente.
    """

    carpeta = Path(carpeta)
    cifrados = carpeta / "cifrados"
    recuperados = carpeta / "recuperados"

    semilla = (
        carpeta / "semilla_laboratorio.bin"
    ).read_bytes()

    recuperados.mkdir(parents=True, exist_ok=True)

    for archivo in sorted(cifrados.glob("*.enc.json")):
        resultado = descifrar_archivo(
            archivo,
            recuperados,
            semilla,
            ID_LABORATORIO
        )

        print(f"RECUPERADO: {resultado.name}")


def demostracion():
    """
    Ejecuta el ciclo completo sobre archivos sinteticos.
    """

    print("=== DEMOSTRACION MODELO B ===")

    with tempfile.TemporaryDirectory(
        prefix="criptografia_laboratorio_"
    ) as temporal:

        carpeta = Path(temporal)
        originales = carpeta / "originales"
        recuperados = carpeta / "recuperados"

        originales.mkdir()

        # Solo se crean archivos ficticios.
        archivos = {
            "documento.txt": (
                b"Documento ficticio para el laboratorio."
            ),
            "datos.csv": (
                b"id,valor\n1,100\n2,200\n"
            ),
            "notas.txt": (
                b"Prueba de recuperacion criptografica."
            )
        }

        for nombre, contenido in archivos.items():
            (originales / nombre).write_bytes(contenido)

        print("\nFASE 1: CIFRADO")
        ejecutar_proceso("cifrar", carpeta)

        print("\nFASE 2: RECUPERACION")
        ejecutar_proceso("recuperar", carpeta)

        print("\nFASE 3: VERIFICACION DE INTEGRIDAD")

        resultados = []

        for nombre in archivos:
            original = originales / nombre
            recuperado = recuperados / nombre

            if not recuperado.is_file():
                raise AssertionError(
                    f"No se recupero: {nombre}"
                )

            hash_original = calcular_sha256(original)
            hash_recuperado = calcular_sha256(recuperado)

            identicos = (
                original.read_bytes() == recuperado.read_bytes()
                and hash_original == hash_recuperado
            )

            resultados.append(identicos)

            print(
                f"{nombre}: "
                f"{'IDENTICO' if identicos else 'DIFERENTE'}"
            )

            if not identicos:
                raise AssertionError(
                    f"Fallo de integridad: {nombre}"
                )

        resumen = {
            "resultado": (
                "APROBADO" if all(resultados)
                else "RECHAZADO"
            ),
            "modelo": "B",
            "generador_profesor": True,
            "procesos_independientes": 2,
            "archivos_verificados": len(resultados),
            "integridad_correcta": all(resultados)
        }

        print("\n=== RESULTADO FINAL ===")
        print(
            json.dumps(
                resumen,
                indent=2,
                ensure_ascii=False
            )
        )

        return 0 if all(resultados) else 1


def main():
    if len(sys.argv) == 1:
        return demostracion()

    if len(sys.argv) != 3:
        raise ValueError(
            "Argumentos incorrectos"
        )

    fase = sys.argv[1]
    carpeta = Path(sys.argv[2])

    if fase == "cifrar":
        fase_cifrado(carpeta)
        return 0

    if fase == "recuperar":
        fase_recuperacion(carpeta)
        return 0

    raise ValueError("Fase desconocida")


if __name__ == "__main__":
    raise SystemExit(main())
