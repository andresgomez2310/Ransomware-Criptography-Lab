
import pytest

from compartido.firmas import (
    generar_claves_firma
)

from servidor.firmas_servidor import (
    firmar_respuesta_registro
)

from victima.cliente import (
    verificar_registro_firmado
)


def crear_mensaje_legitimo():
    return {
        "tipo": "registro_ok",
        "idV": "victima-laboratorio",
        "pkS": "CLAVE_PUBLICA_RSA_LEGITIMA"
    }


def test_sustitucion_sin_verificacion():
    """
    Demuestra el problema de confiar en pkS
    sin comprobar su autenticidad.
    """

    mensaje = crear_mensaje_legitimo()

    # Simulacion de una sustitucion de clave
    mensaje["pkS"] = "CLAVE_PUBLICA_RSA_FALSA"

    # Un receptor que no verifica firmas acepta
    # directamente el valor recibido.
    clave_aceptada = mensaje["pkS"]

    assert clave_aceptada == "CLAVE_PUBLICA_RSA_FALSA"


def test_sustitucion_detectada_con_firma():
    """
    Una respuesta firmada no debe aceptarse
    cuando se altera su clave publica RSA.
    """

    privada, publica = generar_claves_firma()

    mensaje = crear_mensaje_legitimo()

    mensaje_firmado = firmar_respuesta_registro(
        mensaje,
        privada
    )

    # El intermediario sustituye la clave,
    # pero no puede producir una firma legitima.
    mensaje_firmado["pkS"] = "CLAVE_PUBLICA_RSA_FALSA"

    with pytest.raises(ValueError):
        verificar_registro_firmado(
            mensaje_firmado,
            publica
        )


def test_firma_de_atacante_rechazada():
    """
    El receptor utiliza la clave de verificacion
    legitima, no la proporcionada por un tercero.
    """

    _, publica_legitima = generar_claves_firma()
    privada_ajena, _ = generar_claves_firma()

    mensaje = crear_mensaje_legitimo()

    mensaje_firmado = firmar_respuesta_registro(
        mensaje,
        privada_ajena
    )

    with pytest.raises(ValueError):
        verificar_registro_firmado(
            mensaje_firmado,
            publica_legitima
        )


def test_mensaje_legitimo_aceptado():
    """
    El mensaje original correctamente firmado
    debe superar la verificacion.
    """

    privada, publica = generar_claves_firma()

    mensaje = crear_mensaje_legitimo()

    mensaje_firmado = firmar_respuesta_registro(
        mensaje,
        privada
    )

    assert verificar_registro_firmado(
        mensaje_firmado,
        publica
    )
