
from collections import Counter

from material_profesor.generador_semillas import (
    generar_semilla_maestra
)
from collections import Counter
from math import log2

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

def analizar_distribucion(cantidad=10000):
    """
    Estudia la longitud efectiva en bits
    de las semillas generadas.
    """

    if cantidad <= 0:
        raise ValueError("Cantidad invalida")

    frecuencias = Counter()

    for _ in range(cantidad):
        semilla = generar_semilla_maestra()

        valor = int.from_bytes(semilla, "big")
        bits = valor.bit_length()

        frecuencias[bits] += 1

    resultados = {}

    for bits in sorted(frecuencias):
        frecuencia = frecuencias[bits]

        resultados[bits] = {
            "frecuencia": frecuencia,
            "porcentaje": round(
                frecuencia / cantidad * 100, 2
            )
        }

    return resultados


def probabilidad_valor(valor):
    """
    Calcula la probabilidad teorica
    de un valor concreto.
    """

    if not 0 <= valor < 2**24:
        return 0.0

    probabilidad = 0.0

    for configuracion in range(16, 25):
        if valor < 2**configuracion:
            probabilidad += (
                1 / 9
            ) * (
                1 / (2**configuracion)
            )

    return probabilidad


def entropia_minima():
    """
    Calcula la min-entropia teorica
    de la distribucion.
    """

    probabilidad_maxima = probabilidad_valor(0)

    return -log2(probabilidad_maxima)

if __name__ == "__main__":
    print("=== ANALISIS TEORICO ===")

    for clave, valor in analizar_espacio().items():
        print(f"{clave}: {valor}")

    print("\n=== ANALISIS DE MUESTRAS ===")

    for clave, valor in analizar_muestras().items():
        print(f"{clave}: {valor}")
