 
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ---------------------------------------------------------------------------
# Utilidades base64
# ---------------------------------------------------------------------------
 
def codificar_base64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")

def decodificar_base64(texto: str) -> bytes:
    return base64.b64decode(texto, validate=True)

# ---------------------------------------------------------------------------
# Derivación de clave  (paso 3: Ki = HMAC-SHA256(sV, codificar8(i)))
# ---------------------------------------------------------------------------

def derivar_clave(semilla: bytes, contador: int) -> bytes:
    """
    Deriva una clave AES-256 de 32 bytes.
    """
    if len(semilla) != 32:
        raise ValueError("La semilla debe tener exactamente 32 bytes")
 
    if not (0 <= contador < 2**64):
        raise ValueError(
            f"Contador fuera de rango: {contador} (debe ser 0 ≤ i < 2**64)"
        )
 
    contador_bytes = contador.to_bytes(8, "big")
    return hmac.new(
        semilla,
        contador_bytes,
        digestmod=hashlib.sha256
    ).digest()

# ---------------------------------------------------------------------------
# AAD  (datos asociados para AES-GCM)
# ---------------------------------------------------------------------------
def construir_aad(id_victima: str, contador: int) -> bytes:
    """
    Construye los datos asociados (AAD) que ligan criptográficamente
    el ciphertext con la identidad de la víctima y el índice del archivo.
    """
    identificador = id_victima.encode("utf-8")
    return (
        len(identificador).to_bytes(4, "big")
        + identificador
        + contador.to_bytes(8, "big")
    )

# ---------------------------------------------------------------------------
# Cifrado 
# ---------------------------------------------------------------------------
def cifrar_archivo(
    ruta_entrada: str | Path,
    ruta_salida:  str | Path,
    semilla:      bytes,
    id_victima:   str,
    contador:     int,
) -> dict:
    """
    Cifra una copia de trabajo con AES-256-GCM.
    No modifica el original.  El resultado es un JSON con todos los
    campos necesarios para descifrar, incluidos idV e i en el AAD.
    """
 
    entrada = Path(ruta_entrada)
    salida  = Path(ruta_salida)
 
    if entrada.resolve() == salida.resolve():
        raise ValueError("Entrada y salida deben ser rutas distintas")
 
    if salida.exists():
        raise FileExistsError(f"El archivo de salida ya existe: {salida}")
 
    datos = entrada.read_bytes()
    clave = derivar_clave(semilla, contador)
    nonce = os.urandom(12)                      # 12 bytes, aleatorio por clave
    aad   = construir_aad(id_victima, contador)
 
    aes = AESGCM(clave)
    resultado = aes.encrypt(nonce, datos, aad)  # ciphertext || tag (16 bytes)
 
    contenido_cifrado = resultado[:-16]
    etiqueta          = resultado[-16:]
 
    registro = {
        "version":    1,
        "idV":        id_victima,
        "archivo":    entrada.name,
        "contador":   contador,
        "nonce":      codificar_base64(nonce),
        "ciphertext": codificar_base64(contenido_cifrado),
        "tag":        codificar_base64(etiqueta),
    }
 
    salida.parent.mkdir(parents=True, exist_ok=True)
    salida.write_text(json.dumps(registro, indent=2), encoding="utf-8")
 
    return registro
# ---------------------------------------------------------------------------
# Descifrado y verificación
# ---------------------------------------------------------------------------
def _validar_nombre_archivo(nombre: str) -> None:
    """
    Rechaza nombres que puedan escapar de la carpeta de destino.
    """
    nombre_path = Path(nombre)
 
    if nombre != nombre_path.name:
        raise ValueError(f"Nombre de archivo con subdirectorio: {nombre!r}")
 
    if nombre in (".", ".."):
        raise ValueError("Nombre de archivo reservado")
 
    # Barras que permiten path traversal
    if "\\" in nombre or "/" in nombre:
        raise ValueError(f"Nombre de archivo con separador de ruta: {nombre!r}")
 
    # Archivos ocultos (p.ej. ".bashrc", ".ssh/authorized_keys")
    if nombre.startswith("."):
        raise ValueError(f"Nombre de archivo oculto no permitido: {nombre!r}")

def descifrar_archivo(
    ruta_cifrada:    str | Path,
    carpeta_destino: str | Path,
    semilla:         bytes,
    id_victima:      str,
) -> Path:
    """
    Verifica la autenticación GCM y, solo si es válida, guarda el resultado.
 
    Una etiqueta inválida lanza InvalidTag (de cryptography) y no escribe
    nada en disco.
    """
 
    registro = json.loads(
        Path(ruta_cifrada).read_text(encoding="utf-8")
    )
 
    # --- Validaciones de metadatos ---
    if registro.get("version") != 1:
        raise ValueError(
            f"Versión de archivo no compatible: {registro.get('version')}"
        )
 
    if registro.get("idV") != id_victima:
        raise ValueError(
            f"idV no coincide: esperado {id_victima!r}, "
            f"encontrado {registro.get('idV')!r}"
        )
 
    contador = registro["contador"]
    if not isinstance(contador, int) or not (0 <= contador < 2**64):
        raise ValueError(f"Contador inválido: {contador!r}")
 
    # --- Reconstrucción criptográfica ---
    clave = derivar_clave(semilla, contador)
    aad   = construir_aad(id_victima, contador)
 
    nonce    = decodificar_base64(registro["nonce"])
    cifrado  = decodificar_base64(registro["ciphertext"])
    etiqueta = decodificar_base64(registro["tag"])
 
    if len(nonce) != 12:
        raise ValueError(f"Nonce inválido: se esperan 12 bytes, hay {len(nonce)}")
    if len(etiqueta) != 16:
        raise ValueError(
            f"Etiqueta inválida: se esperan 16 bytes, hay {len(etiqueta)}"
        )
 
    aes = AESGCM(clave)
 
    # decrypt() lanza InvalidTag si la autenticación falla.
    # En ese caso, la excepción se propaga y no se escribe nada en disco.
    datos = aes.decrypt(nonce, cifrado + etiqueta, aad)
 
    # --- Validación del nombre antes de escribir ---
    nombre = registro["archivo"]
    _validar_nombre_archivo(nombre)
 
    destino = Path(carpeta_destino) / nombre
    if destino.exists():
        raise FileExistsError(
            f"El archivo recuperado ya existe en destino: {destino}"
        )
 
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_bytes(datos)
 
    return destino

# ---------------------------------------------------------------------------
# Comparación byte a byte 
# ---------------------------------------------------------------------------
def comparar_archivos(ruta_original: str | Path,
                      ruta_recuperado: str | Path) -> bool:
    """
    Compara byte a byte el original reservado con el archivo recuperado.
    """
    original   = Path(ruta_original).read_bytes()
    recuperado = Path(ruta_recuperado).read_bytes()
 
    igual = original == recuperado
 
    estado = "IDÉNTICOS" if igual else "DIFIEREN"
    print(
        f"{estado}  {Path(ruta_original).name} "
        f"({len(original)} bytes orig. / {len(recuperado)} bytes recup.)"
    )
    return igual