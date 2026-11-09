
from collections import Counter

from material_profesor.generador_semillas import (
    generar_semilla_maestra
)


BITS_MINIMOS = 16
BITS_MAXIMOS = 24
TAMANO_SEMILLA = 32


def analizar_espacio():
    """Analiza el rango teorico del generador."""

    posibilidades = 2 ** BITS_MAXIMOS
    bits_almacenados = TAMANO_SEMILLA * 8

    return {
        "bits_almacenados": bits_almacenados,
        "bits_maximos": BITS_MAXIMOS,
        "posibilidades": posibilidades,
        "bytes_por_semilla": TAMANO_SEMILLA
    }


def analizar_muestras(cantidad=1000):
    """Observa propiedades de semillas de prueba."""

    if cantidad <= 0:
        raise ValueError("La cantidad debe ser positiva")

    longitudes = Counter()
    valores = []

    for _ in range(cantidad):
        semilla = generar_semilla_maestra()

        longitudes[len(semilla)] += 1
        valor = int.from_bytes(semilla, "big")

        if valor >= 2 ** BITS_MAXIMOS:
            raise ValueError("Semilla fuera del rango esperado")

        valores.append(valor)

    return {
        "muestras": cantidad,
        "longitudes": dict(longitudes),
        "valor_minimo": min(valores),
        "valor_maximo": max(valores),
        "valores_unicos": len(set(valores))
    }


if __name__ == "__main__":
    print("=== ANALISIS TEORICO ===")

    for clave, valor in analizar_espacio().items():
        print(f"{clave}: {valor}")

    print("\n=== ANALISIS DE MUESTRAS ===")

    for clave, valor in analizar_muestras().items():
        print(f"{clave}: {valor}")
