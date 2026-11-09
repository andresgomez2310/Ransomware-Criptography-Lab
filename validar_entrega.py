
import json
import subprocess
import sys

from datetime import datetime, timezone
from pathlib import Path


RAIZ = Path(__file__).resolve().parent
SALIDA = RAIZ / "resultados_laboratorio"


PASOS = [
    (
        "pruebas_pytest",
        [sys.executable, "-m", "pytest", "pruebas", "-q"],
        120
    ),
    (
        "cliente_servidor",
        [sys.executable, "demostracion_cliente_servidor.py"],
        45
    ),
    (
        "integridad",
        [sys.executable, "demostracion_integridad.py"],
        45
    ),
    (
        "investigacion",
        [
            sys.executable,
            "demostracion_investigacion.py",
            "--muestras",
            "2000"
        ],
        45
    ),
    (
        "mitm_firmas",
        [sys.executable, "demostracion_mitm_defensa.py"],
        45
    ),
    (
        "mitm_tcp_local",
        [sys.executable, "-m", "mitm.intermediario"],
        45
    )
]


def ejecutar(nombre, comando, limite):
    try:
        proceso = subprocess.run(
            comando,
            cwd=RAIZ,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=limite,
            check=False
        )

        codigo = proceso.returncode
        salida = proceso.stdout
        errores = proceso.stderr

        estado = (
            "APROBADO"
            if codigo == 0
            else "FALLIDO"
        )

    except subprocess.TimeoutExpired as error:
        codigo = None
        estado = "TIEMPO_AGOTADO"

        salida = error.stdout or ""
        errores = error.stderr or ""

        if isinstance(salida, bytes):
            salida = salida.decode(
                "utf-8",
                errors="replace"
            )

        if isinstance(errores, bytes):
            errores = errores.decode(
                "utf-8",
                errors="replace"
            )

        errores += "\nTiempo maximo superado."

    except OSError as error:
        codigo = None
        estado = "ERROR_EJECUCION"
        salida = ""
        errores = str(error)

    registro = {
        "nombre": nombre,
        "estado": estado,
        "codigo_salida": codigo,
        "comando": comando,
        "stdout": salida,
        "stderr": errores
    }

    ruta_log = SALIDA / f"{nombre}.log"

    ruta_log.write_text(
        (
            f"COMANDO: {' '.join(comando)}\n"
            f"ESTADO: {estado}\n\n"
            f"SALIDA:\n{salida}\n\n"
            f"ERRORES:\n{errores}\n"
        ),
        encoding="utf-8"
    )

    return registro


def main():
    SALIDA.mkdir(
        parents=True,
        exist_ok=True
    )

    resultados = []

    print("=== VALIDACION INTEGRAL DEL LABORATORIO ===")

    for nombre, comando, limite in PASOS:
        print(
            f"\nEjecutando: {nombre}",
            flush=True
        )

        resultado = ejecutar(
            nombre,
            comando,
            limite
        )

        resultados.append(resultado)

        print(
            f"Resultado: {resultado['estado']}",
            flush=True
        )

    aprobados = sum(
        resultado["estado"] == "APROBADO"
        for resultado in resultados
    )

    fallidos = len(resultados) - aprobados

    estado_final = (
        "APROBADO"
        if fallidos == 0
        else "PENDIENTE"
    )

    resumen = {
        "fecha_utc": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds"),
        "total": len(resultados),
        "aprobados": aprobados,
        "fallidos": fallidos,
        "estado": estado_final,
        "pruebas": [
            {
                "nombre": resultado["nombre"],
                "estado": resultado["estado"],
                "codigo_salida": resultado["codigo_salida"]
            }
            for resultado in resultados
        ],
        "alcance": (
            "Valida las pruebas automatizadas y las "
            "demostraciones disponibles. No certifica "
            "los requisitos M1-M6 ni otros escenarios "
            "que no se hayan implementado."
        )
    }

    ruta_resumen = (
        SALIDA / "validacion_final.json"
    )

    ruta_resumen.write_text(
        json.dumps(
            resumen,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print("\n=== RESULTADO FINAL ===")
    print(
        json.dumps(
            resumen,
            indent=2,
            ensure_ascii=False
        )
    )

    print(
        f"\nInforme guardado en: {ruta_resumen}"
    )

    return 0 if fallidos == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
