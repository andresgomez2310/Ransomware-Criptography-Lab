import base64
import json
from copy import deepcopy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from compartido.firmas import generar_claves_firma
from servidor.firmas_servidor import firmar_respuesta_registro
from victima.cliente import verificar_registro_firmado


def clave_rsa_base64():
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = clave.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode("ascii")


def ejecutar_demostracion():
    id_victima = "identidad-ficticia-laboratorio"
    privada_servidor, publica_confiable = generar_claves_firma()
    privada_ajena, _ = generar_claves_firma()
    clave_legitima = clave_rsa_base64()
    clave_sustituida = clave_rsa_base64()
    assert clave_legitima != clave_sustituida

    respuesta = firmar_respuesta_registro(
        {"tipo": "registro_ok", "idV": id_victima, "pkS": clave_legitima},
        privada_servidor,
    )
    resultados = {}

    # Caso 1: respuesta autentica aceptada.
    resultados["mensaje_legitimo_aceptado"] = (
        verificar_registro_firmado(respuesta, publica_confiable) is True
    )

    # Caso 2: receptor inseguro: acepta clave manipulada sin verificar.
    alterada = deepcopy(respuesta)
    alterada["pkS"] = clave_sustituida
    resultados["sin_verificacion_existe_riesgo"] = (
        alterada["pkS"] == clave_sustituida
    )

    # Caso 3: receptor seguro: rechaza clave sustituida.
    try:
        verificar_registro_firmado(alterada, publica_confiable)
        resultados["clave_sustituida_rechazada"] = False
    except ValueError:
        resultados["clave_sustituida_rechazada"] = True

    # Caso 4: firma de tercero no reemplaza la confianza previa.
    falsificada = firmar_respuesta_registro(
        {"tipo": "registro_ok", "idV": id_victima, "pkS": clave_sustituida},
        privada_ajena,
    )
    try:
        verificar_registro_firmado(falsificada, publica_confiable)
        resultados["firma_ajena_rechazada"] = False
    except ValueError:
        resultados["firma_ajena_rechazada"] = True

    # Caso 5: alterar idV tambien invalida la firma legitima.
    identidad_alterada = deepcopy(respuesta)
    identidad_alterada["idV"] = "otra-identidad-ficticia"
    try:
        verificar_registro_firmado(identidad_alterada, publica_confiable)
        resultados["identidad_alterada_rechazada"] = False
    except ValueError:
        resultados["identidad_alterada_rechazada"] = True

    informe = {
        "demostracion": "defensa ante sustitucion de clave publica",
        "escenario": "mensajes sinteticos en memoria, sin red",
        "resultados": resultados,
        "pruebas_aprobadas": sum(resultados.values()),
        "pruebas_totales": len(resultados),
        "estado": "APROBADO" if all(resultados.values()) else "FALLIDO",
    }
    print(json.dumps(informe, indent=2, ensure_ascii=False))
    return 0 if all(resultados.values()) else 1


if __name__ == "__main__":
    raise SystemExit(ejecutar_demostracion())