import argparse
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
DIRECTORIOS_CODIGO = (
    "compartido", "servidor", "victima", "investigacion", "mitm",
    "pruebas", "material_profesor", "archivos_prueba",
)
EXTENSIONES_PERMITIDAS = {".py", ".txt", ".md", ".csv", ".pdf"}
ARCHIVOS_RAIZ = {"README.md", "requirements.txt"}


def archivos_entregables():
    for nombre in sorted(ARCHIVOS_RAIZ):
        ruta = RAIZ / nombre
        if ruta.is_file() and not ruta.is_symlink():
            yield ruta, ruta.relative_to(RAIZ).as_posix()

    for ruta in sorted(RAIZ.glob("*.py")):
        if ruta.is_file() and not ruta.is_symlink():
            yield ruta, ruta.name

    for directorio in DIRECTORIOS_CODIGO:
        raiz = RAIZ / directorio
        if not raiz.is_dir() or raiz.is_symlink():
            continue
        for ruta in sorted(raiz.rglob("*")):
            if not ruta.is_file() or ruta.is_symlink():
                continue
            partes = ruta.relative_to(RAIZ).parts
            if any(p.startswith(".") or p == "__pycache__" for p in partes):
                continue
            if ruta.suffix.lower() in EXTENSIONES_PERMITIDAS:
                yield ruta, ruta.relative_to(RAIZ).as_posix()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--informe", type=Path, help="Informe PDF del equipo")
    parser.add_argument("--salida", type=Path, default=RAIZ / "ActividadIII_ENTREGA.zip")
    args = parser.parse_args()

    pendientes = []
    readme = RAIZ / "README.md"
    if not readme.is_file() or not readme.read_text(encoding="utf-8").strip():
        pendientes.append("README.md ausente o vacio")

    informe = args.informe.resolve() if args.informe else None
    if informe is None:
        pendientes.append("Informe PDF no indicado (usa --informe)")
    elif not informe.is_file() or informe.suffix.lower() != ".pdf":
        parser.error("El informe debe existir y tener extension .pdf")

    verificacion = RAIZ / "resultados_laboratorio" / "validacion_final.json"
    if verificacion.is_file():
        try:
            datos = json.loads(verificacion.read_text(encoding="utf-8"))
            if datos.get("estado") != "APROBADO" or datos.get("fallidos") != 0:
                pendientes.append("La validacion automatizada no esta aprobada")
        except (OSError, ValueError):
            pendientes.append("No se pudo leer validacion_final.json")
    else:
        pendientes.append("Falta resultados_laboratorio/validacion_final.json")

    # Los escenarios del PDF no se certifican con el validador de 6 pasos.
    observacion = (
        "Las seis comprobaciones automatizadas no certifican el ciclo completo "
        "de recuperacion por pago, investigacion real ni MITM M1-M6. "
        "Revisar y documentar estas cuatro pruebas antes de la entrega definitiva."
    )

    estado = "BORRADOR" if pendientes else "DOCUMENTACION_PRESENTE_POR_REVISAR"
    manifest = {
        "fecha_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "estado": estado,
        "pendientes_documentales": pendientes,
        "advertencia_de_alcance": observacion,
        "archivos_privados_excluidos": True,
    }
    salida = args.salida.resolve()
    salida.parent.mkdir(parents=True, exist_ok=True)