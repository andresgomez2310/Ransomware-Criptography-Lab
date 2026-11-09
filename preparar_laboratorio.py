import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from victima.cliente import preparar_identidad, CARPETA_ESTADO
from servidor.almacenamiento import preparar_servidor, CARPETA as CARPETA_SRV
from servidor.firmas_servidor import preparar_firmas_servidor


def main():
    print("=== Preparación del laboratorio ===\n")

    # 1. Identidad de la víctima
    identidad = preparar_identidad()
    idV = identidad["idV"]
    print(f"idV de la víctima: {idV}")

    pkV_pem = identidad["clave_publica"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pkV_b64 = base64.b64encode(pkV_pem).decode("ascii")

    # 2. Autorizar en el servidor
    CARPETA_SRV.mkdir(parents=True, exist_ok=True)
    ruta_auth = CARPETA_SRV / "identidades_autorizadas.json"
    if ruta_auth.exists():
        auth = json.loads(ruta_auth.read_text(encoding="utf-8"))
    else:
        auth = {}
    auth[idV] = pkV_b64
    ruta_auth.write_text(json.dumps(auth, indent=2), encoding="utf-8")
    print(f"Autorizada en: {ruta_auth}")

    # 3. Asegurar identidad del servidor + firmas Ed25519
    preparar_servidor(CARPETA_SRV)
    firmas = preparar_firmas_servidor(CARPETA_SRV)
    publica_ed = firmas["publica"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # 4. Entregar clave de confianza a la víctima
    CARPETA_ESTADO.mkdir(parents=True, exist_ok=True)
    ruta_conf = CARPETA_ESTADO / "servidor_confiable.pem"
    ruta_conf.write_bytes(publica_ed)
    print(f"Clave de confianza del servidor → {ruta_conf}")

    print("\nListo. Ahora puedes ejecutar:")
    print("  Terminal 1:  python -m servidor.servidor")
    print("  Terminal 2:  python -m victima.aplicacion incidente")
    print("  (después)    python -m victima.aplicacion pago")


if __name__ == "__main__":
    main()