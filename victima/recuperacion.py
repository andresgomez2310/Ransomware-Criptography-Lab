
import hashlib
from pathlib import Path

from victima.cifrado import descifrar_archivo


def calcular_sha256(ruta):
    """Calcula el SHA-256 de un archivo."""

    digest = hashlib.sha256()

    with open(ruta, "rb") as archivo:
        for bloque in iter(
            lambda: archivo.read(65536),
            b""
        ):
            digest.update(bloque)

    return digest.hexdigest()


def verificar_archivos(original, recuperado):
    """Comprueba que ambos archivos sean identicos."""

    original = Path(original)
    recuperado = Path(recuperado)

    if not original.is_file():
        raise FileNotFoundError(original)

    if not recuperado.is_file():
        raise FileNotFoundError(recuperado)

    hash_original = calcular_sha256(original)
    hash_recuperado = calcular_sha256(recuperado)

    return hash_original == hash_recuperado


def recuperar_y_verificar(
    ruta_cifrada,
    carpeta_recuperados,
    semilla,
    id_victima,
    ruta_original
):
    """
    Recupera un archivo de laboratorio
    y comprueba su integridad.
    """

    recuperado = descifrar_archivo(
        ruta_cifrada,
        carpeta_recuperados,
        semilla,
        id_victima
    )

    correcto = verificar_archivos(
        ruta_original,
        recuperado
    )

    if not correcto:
        raise ValueError(
            "El archivo recuperado no coincide con el original"
        )

    return {
        "archivo": recuperado.name,
        "recuperado": True,
        "integridad": correcto,
        "sha256": calcular_sha256(recuperado)
    }
