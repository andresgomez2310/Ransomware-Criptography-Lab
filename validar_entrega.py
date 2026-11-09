import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
SALIDA = RAIZ / "resultados_laboratorio"
PASOS = [
    ("pruebas_pytest", [sys.executable, "-m", "pytest", "pruebas", "-q"], 120),
    ("integridad", [sys.executable, "demostracion_integridad.py"], 45),
    ("investigacion", [sys.executable, "demostracion_investigacion.py", "--muestras", "2000"], 45),
    ("mitm_firmas", [sys.executable, "demostracion_mitm_defensa.py"], 45),
    ("mitm_tcp_local", [sys.executable, "-m", "mitm.intermediario"], 45),
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
            check=False,
        )
        codigo, salida, errores = proceso.returncode, proceso.stdout, proceso.stderr
        estado = "APROBADO" if codigo == 0 else "FALLIDO"
    except subprocess.TimeoutExpired as exc:
        codigo, estado = None, "TIEMPO_AGOTADO"
        salida = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        errores = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        errores += "\nEl proceso supero el tiempo maximo."
    except OSError as exc:
        codigo, estado, salida, errores = None, "ERROR_EJECUCION", "", str(exc)

    registro = {
        "nombre": nombre,
        "estado": estado,
        "codigo_salida": codigo,
        "comando": comando,
        "stdout": salida,
        "stderr": errores,
    }
    (SALIDA / f"{nombre}.log").write_text(
        f"COMANDO: {' '.join(comando)}\nESTADO: {estado}\n\nSALIDA:\n{salida}\n\nERRORES:\n{errores}",
        encoding="utf-8",
    )
    return registro


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    resultados = []
    for nombre, comando, limite in PASOS:
        print(f"Ejecutando {nombre}...", flush=True)
        resultado = ejecutar(nombre, comando, limite)
        resultados.append(resultado)
        print(f"  {resultado['estado']}", flush=True)

    resumen = {
        "fecha_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": len(resultados),
        "aprobados": sum(r["estado"] == "APROBADO" for r in resultados),
        "fallidos": sum(r["estado"] != "APROBADO" for r in resultados),
        "estado": "APROBADO" if all(r["estado"] == "APROBADO" for r in resultados) else "PENDIENTE",
        "pruebas": [
            {"nombre": r["nombre"], "estado": r["estado"], "codigo_salida": r["codigo_salida"]}
            for r in resultados
        ],
        "alcance": "Suite y demostraciones defensivas existentes; no certifica requisitos ausentes del enunciado.",
    }
    archivo = SALIDA / "validacion_final.json"
    archivo.write_text(json.dumps(resumen, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\n" + json.dumps(resumen, indent=2, ensure_ascii=False))
    print(f"\nInforme guardado en: {archivo}")
    return 0 if resumen["estado"] == "APROBADO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
