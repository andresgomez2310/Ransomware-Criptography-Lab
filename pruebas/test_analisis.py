
import pytest

from investigacion.analisis import (
    analizar_espacio,
    analizar_muestras
)


def test_espacio_teorico():
    resultado = analizar_espacio()

    assert resultado["bits_almacenados"] == 256
    assert resultado["bits_maximos"] == 24
    assert resultado["posibilidades"] == 2**24


def test_longitud_muestras():
    resultado = analizar_muestras(100)

    assert resultado["muestras"] == 100
    assert resultado["longitudes"] == {32: 100}


def test_rango_muestras():
    resultado = analizar_muestras(100)

    assert resultado["valor_minimo"] >= 0
    assert resultado["valor_maximo"] < 2**24


def test_cantidad_invalida():
    with pytest.raises(ValueError):
        analizar_muestras(0)
