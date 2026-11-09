import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path

from investigacion.analisis import (
    analizar_espacio,
    analizar_muestras,
    analizar_distribucion,
    entropia_minima,
    probabilidad_valor,
)


def construir_resultados(cantidad: int) -> dict:
    if not isinstance(cantidad, int) or isinstance(cantidad, bool) or cantidad < 1:
        raise ValueError("El número de muestras debe ser un entero positivo")

    espacio = analizar_espacio()
    muestras = analizar_muestras(cantidad)
    distribucion = analizar_distribucion(cantidad)
    min_entropia = entropia_minima()

    # Las verificaciones evitan publicar mediciones incoherentes.
    assert espacio["bytes_por_semilla"] == 32
    assert espacio["bits_almacenados"] == 256
    assert espacio["bits_maximos"] == 24
    assert espacio["posibilidades"] == 2**24
    assert muestras["muestras"] == cantidad
    assert muestras["longitudes"] == {32: cantidad}
    assert 0 <= muestras["valor_minimo"] <= muestras["valor_maximo"] < 2**24
    assert 1 <= muestras["valores_unicos"] <= cantidad
    assert sum(item["frecuencia"] for item in distribucion.values()) == cantidad
    assert all(0 <= int(bits) <= 24 for bits in distribucion)
    assert math.isclose(min_entropia, -math.log2(probabilidad_valor(0)), rel_tol=1e-12)

    return {
        "experimento": "Análisis estadístico del generador entregado por el profesor",
        "fecha_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "muestras_por_experimento": cantidad,
        "espacio_teorico": espacio,
        "min_entropia_bits": round(min_entropia, 6),
        "maxima_probabilidad_por_valor": probabilidad_valor(0),
        "medicion_de_muestras": muestras,
        "frecuencia_longitud_efectiva_bits": {
            str(bits): valores for bits, valores in distribucion.items()
        },
        "interpretacion": (
            "Aunque la semilla ocupa 256 bits en memoria, el generador solo "
            "produce valores inferiores a 2^24. Su distribución no es uniforme; "
            "la min-entropía es menor que 24 bits."
        ),
        "limitacion": (
            "Las mediciones son aleatorias y pueden variar entre ejecuciones. "
            "No se recuperan semillas ajenas ni se mide un ataque sobre claves reales."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--muestras", type=int, default=10000)
    parser.add_argument(
        "--salida",
        type=Path,
        default=Path("resultados_laboratorio/investigacion_generador.json"),
    )
    args = parser.parse_args()
    try:
        resultado = construir_resultados(args.muestras)
    except (ValueError, AssertionError) as exc:
        parser.error(f"Error de validación del experimento: {exc}")

    args.salida.parent.mkdir(parents=True, exist_ok=True)
    args.salida.write_text(
        json.dumps(resultado, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("=== INVESTIGACIÓN DEL GENERADOR ===")
    print("Estado: APROBADO (verificaciones estadísticas internas)")
    print(f"Muestras: {args.muestras}")
    print("Longitud almacenada: 256 bits")
    print("Máximo de bits efectivos: 24")
    print(f"Min-entropía teórica: {resultado['min_entropia_bits']:.4f} bits")
    print(f"Valores distintos observados: {resultado['medicion_de_muestras']['valores_unicos']}")
    print(f"Resultados: {args.salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())