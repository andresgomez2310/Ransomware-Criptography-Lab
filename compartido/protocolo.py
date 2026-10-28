
import json

MAX_MENSAJE = 1024 * 1024


def enviar_mensaje(conexion, mensaje):
    """
    Convierte un diccionario en JSON
    y lo envia mediante TCP.
    """

    if not isinstance(mensaje, dict):
        raise TypeError("El mensaje debe ser un diccionario")

    if "tipo" not in mensaje:
        raise ValueError("El mensaje debe incluir 'tipo'")

    datos = (
        json.dumps(mensaje, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    if len(datos) > MAX_MENSAJE:
        raise ValueError("Mensaje demasiado grande")

    conexion.sendall(datos)


def recibir_mensaje(conexion):
    """
    Recibe un mensaje JSON completo
    desde una conexion TCP.
    """

    datos = bytearray()

    while True:
        caracter = conexion.recv(1)

        if not caracter:
            raise ConnectionError(
                "La conexion se cerro inesperadamente"
            )

        if caracter == b"\n":
            break

        datos.extend(caracter)

        if len(datos) >= MAX_MENSAJE:
            raise ValueError("Mensaje demasiado grande")

    mensaje = json.loads(datos.decode("utf-8"))

    if not isinstance(mensaje, dict):
        raise ValueError("El JSON debe ser un objeto")

    if not isinstance(mensaje.get("tipo"), str):
        raise ValueError("El mensaje requiere un tipo valido")

    return mensaje
