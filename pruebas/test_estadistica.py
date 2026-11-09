
import pytest

from investigacion.analisis import (
    analizar_distribucion,
    probabilidad_valor,
    entropia_minima
)


def test_distribucion():
    cantidad = 1000

    resultado = analizar_distribucion(cantidad)

    total = sum(
        datos["frecuencia"]
        for datos in resultado.values()
    )

    assert total == cantidad
    assert all(0 <= bits <= 24 for bits in resultado)


def test_probabilidad_valor():
    probabilidad = probabilidad_valor(0)

    assert 0 < probabilidad < 1

    assert probabilidad_valor(2**24) == 0

    assert (
        probabilidad_valor(0)
        > probabilidad_valor(2**23)
    )


def test_entropia_minima():
    resultado = entropia_minima()

    assert 0 < resultado < 24


def test_cantidad_invalida():
    with pytest.raises(ValueError):
        analizar_distribucion(0)
