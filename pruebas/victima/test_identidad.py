
import victima.cliente as cliente


def configurar_entorno(tmp_path, monkeypatch):
    carpeta = tmp_path / "victima"

    monkeypatch.setattr(
        cliente, "CARPETA_ESTADO", carpeta
    )
    monkeypatch.setattr(
        cliente, "ARCHIVO_IDENTIDAD",
        carpeta / "identidad.json"
    )
    monkeypatch.setattr(
        cliente, "ARCHIVO_PRIVADO",
        carpeta / "privada.pem"
    )
    monkeypatch.setattr(
        cliente, "ARCHIVO_PUBLICO",
        carpeta / "publica.pem"
    )


def test_identidad_persistente(tmp_path, monkeypatch):
    configurar_entorno(tmp_path, monkeypatch)

    primera = cliente.preparar_identidad()
    segunda = cliente.preparar_identidad()

    assert primera["idV"] == segunda["idV"]
    assert (
        primera["clave_privada"].private_numbers()
        == segunda["clave_privada"].private_numbers()
    )


def test_archivos_creados(tmp_path, monkeypatch):
    configurar_entorno(tmp_path, monkeypatch)

    identidad = cliente.preparar_identidad()

    assert cliente.ARCHIVO_IDENTIDAD.exists()
    assert cliente.ARCHIVO_PRIVADO.exists()
    assert cliente.ARCHIVO_PUBLICO.exists()

    assert identidad["clave_privada"].key_size >= 2048


def test_mensaje_registro(tmp_path, monkeypatch):
    import base64

    configurar_entorno(tmp_path, monkeypatch)

    identidad = cliente.preparar_identidad()
    mensaje = cliente.crear_mensaje_registro(identidad)

    assert mensaje["tipo"] == "registro"
    assert mensaje["idV"] == identidad["idV"]

    pem = base64.b64decode(
        mensaje["pkV"],
        validate=True
    )

    assert b"BEGIN PUBLIC KEY" in pem

def test_estado_incompleto(tmp_path, monkeypatch):
    import pytest

    configurar_entorno(tmp_path, monkeypatch)

    cliente.CARPETA_ESTADO.mkdir(parents=True)
    cliente.ARCHIVO_IDENTIDAD.write_text(
        '{"idV": "victima-prueba"}',
        encoding="utf-8"
    )

    with pytest.raises(RuntimeError):
        cliente.preparar_identidad()
