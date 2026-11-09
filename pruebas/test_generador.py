
from material_profesor.generador_semillas import (
    generar_semilla_maestra
)
from victima.cifrado import derivar_clave


def test_longitud_semilla():
    semilla = generar_semilla_maestra()

    assert isinstance(semilla, bytes)
    assert len(semilla) == 32


def test_rango_semilla():
    for _ in range(100):
        semilla = generar_semilla_maestra()

        valor = int.from_bytes(semilla, "big")

        assert 0 <= valor < 2**24


def test_compatibilidad_hmac():

    semilla = generar_semilla_maestra()
    clave = derivar_clave(semilla, 0)

    assert len(clave) == 32
