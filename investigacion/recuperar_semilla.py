import argparse
import base64
import hashlib
import hmac
import json
import tempfile
import time
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAXIMO = 1 << 24

def recuperar(carpeta_cifrados, carpeta_salida, limite=MAXIMO):
    carpeta = Path(carpeta_cifrados)
    salidas = sorted(carpeta.glob('*.enc.json'))
    if not salidas:
        raise ValueError('No se encontraron archivos .enc.json')
    if not (1 <= limite <= MAXIMO):
        raise ValueError('El limite debe estar entre 1 y 16777216')
    registros = [json.loads(p.read_text(encoding='utf-8')) for p in salidas]
    ids = {r['idV'] for r in registros}
    if len(ids) != 1:
        raise ValueError('Los archivos pertenecen a distintas identidades')
    def verificar(semilla, registro):
        contador = registro['contador']
        if type(contador) is not int or not (0 <= contador < 2**64):
            raise ValueError('Contador invalido')
        identificador = registro['idV'].encode('utf-8')
        aad = (len(identificador).to_bytes(4, 'big') + identificador
               + contador.to_bytes(8, 'big'))
        clave = hmac.new(semilla, contador.to_bytes(8, 'big'), hashlib.sha256).digest()
        nonce = base64.b64decode(registro['nonce'], validate=True)
        cifrado = base64.b64decode(registro['ciphertext'], validate=True)
        tag = base64.b64decode(registro['tag'], validate=True)
        if len(nonce) != 12 or len(tag) != 16:
            raise ValueError('Nonce o etiqueta invalidos')
        return AESGCM(clave).decrypt(nonce, cifrado + tag, aad)

    inicio = time.perf_counter()
    semilla = None
    intentos = 0
    for numero in range(limite):
        intentos += 1
        candidata = numero.to_bytes(32, 'big')
        try:
            verificar(candidata, registros[0])
        except InvalidTag:
            continue
        # La etiqueta autentica es evidencia criptografica de la candidata.
        semilla = candidata
        break
    duracion_busqueda = time.perf_counter() - inicio
    if semilla is None:
        return {'estado': 'NO_ENCONTRADA', 'candidatos': intentos,
                'segundos_busqueda': round(duracion_busqueda, 3)}

    # Validar absolutamente todos los archivos antes de escribir ninguno.
    recuperados = [verificar(semilla, registro) for registro in registros]
    destino = Path(carpeta_salida)
    if destino.resolve() == carpeta.resolve():
        raise ValueError('La salida debe estar en otra carpeta')
    nombres = [r['archivo'] for r in registros]
    if len(nombres) != len(set(nombres)):
        raise ValueError('Nombres duplicados')
    for nombre in nombres:
        if not isinstance(nombre, str) or not nombre or nombre.startswith('.') or '/' in nombre or '\\' in nombre or ':' in nombre:
            raise ValueError('Nombre de salida inseguro')
        if (destino / nombre).exists():
            raise FileExistsError(destino / nombre)
    destino.mkdir(parents=True, exist_ok=True)
    for nombre, contenido in zip(nombres, recuperados):
        (destino / nombre).write_bytes(contenido)
    return {'estado': 'RECUPERADA', 'candidatos': intentos,
            'segundos_busqueda': round(duracion_busqueda, 3),
            'archivos_recuperados': len(recuperados),
            'verificacion': 'AES-GCM', 'carpeta_salida': str(destino)}


def demo():
    # Datos ficticios y semilla predefinida solamente para validar el algoritmo.
    from victima.cifrado import cifrar_archivo
    with tempfile.TemporaryDirectory(prefix='investigacion_demo_') as temporal:
        base = Path(temporal)
        entrada = base / 'originales'
        cifrados = base / 'cifrados'
        salida = base / 'recuperados'
        entrada.mkdir()
        cifrados.mkdir()
        datos = {'documento.txt': b'Experimento de criptografia',
                 'datos.csv': b'id,valor\n1,100\n2,200\n'}
        semilla = (1234).to_bytes(32, 'big')
        for i, (nombre, contenido) in enumerate(datos.items()):
            ruta = entrada / nombre
            ruta.write_bytes(contenido)
            cifrar_archivo(ruta, cifrados / (nombre + '.enc.json'), semilla, 'laboratorio', i)
        resultado = recuperar(cifrados, salida, limite=2000)
        if resultado['estado'] != 'RECUPERADA' or any((salida / n).read_bytes() != b for n, b in datos.items()):
            raise AssertionError('La demostracion de recuperacion fallo')
        resultado['comparacion_final'] = 'IDENTICOS'
        print(json.dumps(resultado, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true', help='Laboratorio ficticio autocontenido')
    parser.add_argument('--cifrados', type=Path)
    parser.add_argument('--salida', type=Path)
    parser.add_argument('--limite', type=int, default=MAXIMO)
    args = parser.parse_args()
    if args.demo:
        demo()
    elif args.cifrados and args.salida:
        print(json.dumps(recuperar(args.cifrados, args.salida, args.limite), indent=2, ensure_ascii=False))
    else:
        parser.error('Usa --demo o indica --cifrados y --salida')

if __name__ == '__main__':
    main()
