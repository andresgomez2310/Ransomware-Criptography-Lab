
import argparse
import base64
import hashlib
import hmac
import json
import platform
import sys
import tempfile
import time

from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAXIMO = 1 << 24


def verificar(semilla, registro):
    """Verifica y descifra un archivo de laboratorio."""

    contador = registro["contador"]

    if type(contador) is not int or not (0 <= contador < 2**64):
        raise ValueError("Contador invalido")

    id_victima = registro["idV"]

    if not isinstance(id_victima, str):
        raise ValueError("Identificador invalido")

    identificador = id_victima.encode("utf-8")

    aad = (
        len(identificador).to_bytes(4, "big")
        + identificador
        + contador.to_bytes(8, "big")
    )

    clave = hmac.new(
        semilla,
        contador.to_bytes(8, "big"),
        hashlib.sha256
    ).digest()

    nonce = base64.b64decode(
        registro["nonce"],
        validate=True
    )

    cifrado = base64.b64decode(
        registro["ciphertext"],
        validate=True
    )

    etiqueta = base64.b64decode(
        registro["tag"],
        validate=True
    )

    if len(nonce) != 12 or len(etiqueta) != 16:
        raise ValueError("Nonce o etiqueta invalidos")

    return AESGCM(clave).decrypt(
        nonce,
        cifrado + etiqueta,
        aad
    )


def recuperar(carpeta_cifrados, carpeta_salida, limite=MAXIMO):
    """
    Recuperacion experimental sobre archivos
    proporcionados expresamente para el laboratorio.

    Registra por separado los costos de busqueda
    y descifrado.
    """

    carpeta = Path(carpeta_cifrados)
    destino = Path(carpeta_salida)

    salidas = sorted(carpeta.glob("*.enc.json"))

    if not salidas:
        raise ValueError(
            "No se encontraron archivos .enc.json"
        )

    if not (1 <= limite <= MAXIMO):
        raise ValueError(
            "El limite debe estar entre 1 y 16777216"
        )

    if destino.resolve() == carpeta.resolve():
        raise ValueError(
            "La salida debe estar en otra carpeta"
        )

    registros = [
        json.loads(
            ruta.read_text(encoding="utf-8")
        )
        for ruta in salidas
    ]

    ids = {registro["idV"] for registro in registros}

    if len(ids) != 1:
        raise ValueError(
            "Los archivos pertenecen a distintas identidades"
        )

    # Validar nombres antes de escribir archivos.
    nombres = [registro["archivo"] for registro in registros]

    if len(nombres) != len(set(nombres)):
        raise ValueError("Nombres duplicados")

    for nombre in nombres:
        if (
            not isinstance(nombre, str)
            or not nombre
            or nombre.startswith(".")
            or "/" in nombre
            or "\\" in nombre
            or ":" in nombre
            or nombre in (".", "..")
        ):
            raise ValueError(
                "Nombre de salida inseguro"
            )

        if (destino / nombre).exists():
            raise FileExistsError(destino / nombre)

    # FASE 1: Busqueda experimental.
    inicio_busqueda = time.perf_counter()

    semilla = None
    intentos = 0

    for numero in range(limite):
        intentos += 1
        candidata = numero.to_bytes(32, "big")

        try:
            verificar(candidata, registros[0])

        except InvalidTag:
            continue

        semilla = candidata
        break

    segundos_busqueda = (
        time.perf_counter() - inicio_busqueda
    )

    velocidad = (
        intentos / segundos_busqueda
        if segundos_busqueda > 0
        else None
    )

    entorno = {
        "python": sys.version.split()[0],
        "sistema": platform.system(),
        "arquitectura": platform.machine(),
        "procesador": platform.processor()
    }

    if semilla is None:
        return {
            "estado": "NO_ENCONTRADA",
            "candidatos": intentos,
            "segundos_busqueda": round(
                segundos_busqueda, 6
            ),
            "candidatos_por_segundo": (
                round(velocidad, 2)
                if velocidad is not None
                else None
            ),
            "entorno": entorno
        }

    # FASE 2: Descifrado de todos los archivos.
    inicio_descifrado = time.perf_counter()

    recuperados = [
        verificar(semilla, registro)
        for registro in registros
    ]

    segundos_descifrado = (
        time.perf_counter() - inicio_descifrado
    )

    bytes_recuperados = sum(
        len(contenido)
        for contenido in recuperados
    )

    # Solo se escriben salidas tras validar todos
    # los archivos con AES-GCM.
    destino.mkdir(parents=True, exist_ok=True)

    for nombre, contenido in zip(nombres, recuperados):
        (destino / nombre).write_bytes(contenido)

    segundos_total_criptografia = (
        segundos_busqueda + segundos_descifrado
    )

    return {
        "estado": "RECUPERADA",
        "candidatos": intentos,
        "limite_candidatos": limite,
        "segundos_busqueda": round(
            segundos_busqueda, 6
        ),
        "segundos_descifrado": round(
            segundos_descifrado, 6
        ),
        "segundos_total_criptografia": round(
            segundos_total_criptografia, 6
        ),
        "candidatos_por_segundo": (
            round(velocidad, 2)
            if velocidad is not None
            else None
        ),
        "archivos_recuperados": len(recuperados),
        "bytes_recuperados": bytes_recuperados,
        "verificacion": "AES-GCM",
        "carpeta_salida": str(destino),
        "entorno": entorno,
        "alcance": (
            "Busqueda experimental sobre archivos "
            "de laboratorio. Los tiempos excluyen "
            "lectura inicial y escritura final."
        )
    }


def demo():
    """
    Demostracion autocontenida usando una semilla
    sintetica conocida por el experimento.

    No representa la recuperacion completa del
    incidente del Modelo B.
    """

    from victima.cifrado import cifrar_archivo

    with tempfile.TemporaryDirectory(
        prefix="investigacion_demo_"
    ) as temporal:

        base = Path(temporal)
        entrada = base / "originales"
        cifrados = base / "cifrados"
        salida = base / "recuperados"

        entrada.mkdir()
        cifrados.mkdir()

        datos = {
            "documento.txt": (
                b"Experimento de criptografia"
            ),
            "datos.csv": (
                b"id,valor\n1,100\n2,200\n"
            )
        }

        # Semilla exclusivamente sintetica.
        semilla = (1234).to_bytes(32, "big")

        for contador, (nombre, contenido) in enumerate(
            datos.items()
        ):
            ruta = entrada / nombre
            ruta.write_bytes(contenido)

            cifrar_archivo(
                ruta,
                cifrados / (nombre + ".enc.json"),
                semilla,
                "laboratorio",
                contador
            )

        resultado = recuperar(
            cifrados,
            salida,
            limite=2000
        )

        if resultado["estado"] != "RECUPERADA":
            raise AssertionError(
                "La recuperacion experimental fallo"
            )

        comparaciones = {}

        for nombre, contenido in datos.items():
            recuperado = (salida / nombre).read_bytes()

            comparaciones[nombre] = (
                recuperado == contenido
            )

        if not all(comparaciones.values()):
            raise AssertionError(
                "Los archivos recuperados no son identicos"
            )

        resultado["comparacion_final"] = "IDENTICOS"
        resultado["comparaciones"] = comparaciones
        resultado["tipo_experimento"] = (
            "Semilla sintetica predefinida"
        )

        print(
            json.dumps(
                resultado,
                indent=2,
                ensure_ascii=False
            )
        )


def main():
    parser = argparse.ArgumentParser(
        description="Recuperacion experimental del laboratorio"
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Ejecutar demostracion ficticia"
    )

    parser.add_argument(
        "--cifrados",
        type=Path
    )

    parser.add_argument(
        "--salida",
        type=Path
    )

    parser.add_argument(
        "--limite",
        type=int,
        default=MAXIMO
    )

    args = parser.parse_args()

    if args.demo:
        demo()

    elif args.cifrados and args.salida:
        resultado = recuperar(
            args.cifrados,
            args.salida,
            args.limite
        )

        print(
            json.dumps(
                resultado,
                indent=2,
                ensure_ascii=False
            )
        )

    else:
        parser.error(
            "Usa --demo o indica --cifrados y --salida"
        )


if __name__ == "__main__":
    main()
