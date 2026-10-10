"""
Pruebas de seguridad obligatorias P1 a P8 (apartado 5 de la tarea) y pruebas de los RF.

Cada prueba indica qué control criptográfico produce el resultado.
Ejecutar desde la carpeta del proyecto:   python -m pytest -v

Las contraseñas de prueba se generan al azar en cada ejecución, así que no hay
ninguna contraseña escrita en el repositorio.
"""
import hashlib
import json
import os
import secrets
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from buzon_seguro import almacen, bitacora, identidad, paquete
from buzon_seguro.errores import (
    ClaveNoConfiable, ContrasenaIncorrecta, ErrorBuzon, PaqueteRechazado,
)

ANA, BETO, CARLOS, MALLORY = "ana.lopez", "beto.martinez", "carlos.ruiz", "mallory"

@pytest.fixture
def entorno(tmp_path, monkeypatch):
    """Carpeta de datos temporal con Ana, Beto y Carlos ya creados.

    Ana y Beto verificaron sus huellas entre sí. Carlos verificó a Ana.
    """
    monkeypatch.setenv("BUZON_DATOS", str(tmp_path / "datos"))
    claves = {u: secrets.token_urlsafe(16).encode() for u in (ANA, BETO, CARLOS)}
    for usuario, contrasena in claves.items():
        identidad.generar_identidad(usuario, contrasena)
    identidad.marcar_verificada(ANA, BETO)
    identidad.marcar_verificada(BETO, ANA)
    identidad.marcar_verificada(CARLOS, ANA)

    documento = tmp_path / "solicitud_credito_0045.pdf"
    documento.write_bytes(b"%PDF-1.4 Solicitud de credito. Monto: $5,000.00\n" + os.urandom(4096))
    return SimpleNamespace(claves=claves, documento=documento)

def enviar(e) -> dict:
    """Ana cifra y firma el documento para Beto."""
    return paquete.cifrar_para(str(e.documento), ANA, BETO, e.claves[ANA])

def alterar_byte(texto_b64: str, posicion: int = 10) -> str:
    """Invierte un bit de un byte de un campo Base64 (lo que haría un atacante en la red)."""
    datos = bytearray(almacen.desde_b64(texto_b64))
    datos[posicion] ^= 0x01
    return almacen.b64(bytes(datos))

# ─── P1 ─────────────────────────────────────────────────────────────────────
def test_p1_ana_envia_y_beto_descifra(entorno):
    """P1: el documento llega idéntico, el SHA-256 coincide y la firma es válida.

    Controles: ECDH X25519 + HKDF + AES-256-GCM (confidencialidad),
    firma Ed25519 (autenticidad) y SHA-256 del original (integridad, RF6).
    """
    p = enviar(entorno)
    r = paquete.descifrar(p, BETO, entorno.claves[BETO])
    original = entorno.documento.read_bytes()
    assert r["datos"] == original
    assert r["sha256"] == hashlib.sha256(original).hexdigest()
    assert r["metadatos"]["remitente"] == ANA
    # Confidencialidad: el contenido no aparece en claro dentro del paquete.
    assert b"Solicitud de credito" not in json.dumps(p).encode()

# ─── P2 ─────────────────────────────────────────────────────────────────────
def test_p2_un_byte_alterado_en_el_cifrado_se_rechaza(entorno):
    """P2: modificar un solo byte del texto cifrado provoca un rechazo genérico."""
    p = enviar(entorno)
    p["cifrado"] = alterar_byte(p["cifrado"])
    with pytest.raises(PaqueteRechazado):
        paquete.descifrar(p, BETO, entorno.claves[BETO])

def test_p2_actuan_dos_controles_firma_y_etiqueta_gcm(entorno):
    """P2: la firma Ed25519 cubre el cifrado y, además, la etiqueta GCM lo detecta."""
    p = enviar(entorno)
    p["cifrado"] = alterar_byte(p["cifrado"])
    campos = paquete.leer_campos(p)
    with pytest.raises(InvalidSignature):  # control 1: firma del remitente
        paquete.verificar_firma(campos, identidad.cargar_publicas(ANA)["ed25519"])
    clave_beto = identidad.cargar_privada_cifrado(BETO, entorno.claves[BETO])
    with pytest.raises(InvalidTag):        # control 2: etiqueta de autenticación GCM
        paquete.abrir_contenido(campos, clave_beto)

# ─── P3 ─────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("campo, valor", [
    ("destinatario", CARLOS),
    ("fecha", "2026-01-01T00:00:00-06:00"),
])
def test_p3_metadatos_alterados_se_rechazan(entorno, campo, valor):
    """P3: cambiar el destinatario o la fecha se detecta porque los metadatos
    están firmados (Ed25519) y autenticados como AAD de AES-GCM."""
    p = enviar(entorno)
    p["metadatos"][campo] = valor
    with pytest.raises(PaqueteRechazado):
        paquete.descifrar(p, BETO, entorno.claves[BETO])

    campos = paquete.leer_campos(p)
    with pytest.raises(InvalidSignature):  # los metadatos forman parte de lo firmado
        paquete.verificar_firma(campos, identidad.cargar_publicas(ANA)["ed25519"])
    clave_beto = identidad.cargar_privada_cifrado(BETO, entorno.claves[BETO])
    with pytest.raises(InvalidTag):        # el AAD ya no es el mismo
        paquete.abrir_contenido(campos, clave_beto)

# ─── P4 ─────────────────────────────────────────────────────────────────────
def test_p4_carlos_no_puede_descifrar_un_paquete_para_beto(entorno):
    """P4: la firma es auténtica, pero Carlos no puede derivar la clave.

    Control: ECDH. Con la clave privada de Carlos se obtiene otro secreto, HKDF
    produce otra clave AES y la etiqueta GCM no coincide.
    """
    p = enviar(entorno)
    with pytest.raises(PaqueteRechazado):
        paquete.descifrar(p, CARLOS, entorno.claves[CARLOS])

    campos = paquete.leer_campos(p)
    paquete.verificar_firma(campos, identidad.cargar_publicas(ANA)["ed25519"])  # no falla
    clave_carlos = identidad.cargar_privada_cifrado(CARLOS, entorno.claves[CARLOS])
    with pytest.raises(InvalidTag):
        paquete.abrir_contenido(campos, clave_carlos)

# ─── P5 ─────────────────────────────────────────────────────────────────────
def suplantar_en_directorio(victima: str, atacante: str) -> None:
    """Mallory copia SUS claves públicas en el archivo de la víctima (carpeta compartida)."""
    carpeta = almacen.carpeta_directorio()
    falsas = almacen.leer_json(carpeta / f"{atacante}.json")
    falsas["usuario"] = victima
    almacen.escribir_json(carpeta / f"{victima}.json", falsas)

def test_p5_mallory_reemplaza_la_clave_de_ana_y_envia_como_ana(entorno):
    """P5: la huella del directorio ya no coincide con la que Beto verificó.
    Control: verificación de huellas SHA-256 por un segundo canal (RF2).
    """
    clave_mallory = secrets.token_urlsafe(16).encode()
    identidad.generar_identidad(MALLORY, clave_mallory)
    suplantar_en_directorio(ANA, MALLORY)

    metadatos = {"remitente": ANA, "destinatario": BETO,
                "fecha": almacen.ahora_iso(), "archivo": "orden_desembolso.pdf"}
    falso = paquete.construir_paquete(
        b"Desembolsar $10,000 a la cuenta 99-999",
        metadatos,
        identidad.cargar_publicas(BETO)["x25519"],
        identidad.cargar_privada_firma(MALLORY, clave_mallory),
    )
    with pytest.raises(ClaveNoConfiable, match="NO coincide"):
        paquete.descifrar(falso, BETO, entorno.claves[BETO])

def test_p5_sin_tocar_el_directorio_mallory_no_puede_firmar_como_ana(entorno):
    """P5 (variante): si Mallory no reemplaza la clave, su firma no es la de Ana."""
    clave_mallory = secrets.token_urlsafe(16).encode()
    identidad.generar_identidad(MALLORY, clave_mallory)
    metadatos = {"remitente": ANA, "destinatario": BETO,
                "fecha": almacen.ahora_iso(), "archivo": "orden_desembolso.pdf"}
    falso = paquete.construir_paquete(
        b"Desembolsar $10,000", metadatos,
        identidad.cargar_publicas(BETO)["x25519"],
        identidad.cargar_privada_firma(MALLORY, clave_mallory),
    )
    with pytest.raises(PaqueteRechazado):
        paquete.descifrar(falso, BETO, entorno.claves[BETO])

def test_p5_ana_no_cifra_si_reemplazaron_la_clave_de_beto(entorno):
    """P5 (variante de envío): Ana no cifra para una clave de Beto que cambió."""
    identidad.generar_identidad(MALLORY, secrets.token_urlsafe(16).encode())
    suplantar_en_directorio(BETO, MALLORY)
    with pytest.raises(ClaveNoConfiable, match="NO coincide"):
        enviar(entorno)

# ─── P6 ─────────────────────────────────────────────────────────────────────
def test_p6_contrasena_incorrecta_da_un_error_controlado(entorno):
    """P6: la clave privada PKCS#8 no se puede abrir y el mensaje no da detalles."""
    p = enviar(entorno)
    with pytest.raises(ContrasenaIncorrecta) as error:
        paquete.descifrar(p, BETO, b"contrasena-equivocada")
    assert str(error.value) == "No se pudo abrir la clave privada. Verifique la contraseña."
    with pytest.raises(ContrasenaIncorrecta):
        paquete.cifrar_para(str(entorno.documento), ANA, BETO, b"tampoco-es-esta")

# ─── P7 ─────────────────────────────────────────────────────────────────────
def test_p7_auditar_detecta_la_linea_editada(entorno):
    """P7: editar una línea intermedia rompe su hash. Control: hashes SHA-256 encadenados."""
    for _ in range(3):
        enviar(entorno)
    assert bitacora.auditar()["integra"]

    ruta = almacen.ruta_bitacora()
    lineas = ruta.read_text(encoding="utf-8").splitlines()
    intermedia = len(lineas) // 2
    entrada = json.loads(lineas[intermedia])
    entrada["fecha"] = "2020-01-01T00:00:00-06:00"  # el "atacante" cambia la fecha
    lineas[intermedia] = json.dumps(entrada, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    resultado = bitacora.auditar()
    assert not resultado["integra"]
    assert resultado["linea_alterada"] == intermedia + 1  # numeración desde 1

def test_p7_recalcular_el_hash_de_la_linea_rompe_la_cadena(entorno):
    """P7 (variante): si el atacante también recalcula el hash de la línea editada,
    se detecta en la línea siguiente porque su "hash_anterior" ya no coincide."""
    for _ in range(3):
        enviar(entorno)
    ruta = almacen.ruta_bitacora()
    lineas = ruta.read_text(encoding="utf-8").splitlines()
    intermedia = len(lineas) // 2
    entrada = json.loads(lineas[intermedia])
    entrada["fecha"] = "2020-01-01T00:00:00-06:00"
    entrada["hash"] = bitacora._hash_entrada(entrada)
    lineas[intermedia] = json.dumps(entrada, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert bitacora.auditar()["linea_alterada"] == intermedia + 2

# ─── P8 ─────────────────────────────────────────────────────────────────────
def test_p8_mismo_documento_dos_veces_produce_paquetes_distintos(entorno):
    """P8: clave efímera y nonce nuevos en cada envío. Controles: generate() y os.urandom."""
    p1, p2 = enviar(entorno), enviar(entorno)
    for campo in ("efimera_pub", "nonce", "cifrado", "firma"):
        assert p1[campo] != p2[campo]

# ─── Pruebas adicionales de los requerimientos ──────────────────────────────
def test_rf1_claves_privadas_cifradas_con_contrasena(entorno):
    """RF1: los .pem están cifrados (PKCS#8) y no se abren sin la contraseña."""
    carpeta = almacen.carpeta_usuario(ANA)
    for archivo in (identidad.ARCHIVO_X25519, identidad.ARCHIVO_ED25519):
        pem = (carpeta / archivo).read_bytes()
        assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

def test_rf1_rechaza_contrasenas_cortas(entorno):
    with pytest.raises(ErrorBuzon, match="al menos"):
        identidad.generar_identidad("diana.perez", b"corta")

def test_rf2_no_se_cifra_para_un_destinatario_no_verificado(entorno):
    """RF2: Ana nunca verificó a Carlos, así que no puede cifrarle."""
    with pytest.raises(ClaveNoConfiable, match="no está verificado"):
        paquete.cifrar_para(str(entorno.documento), ANA, CARLOS, entorno.claves[ANA])

def test_anexo_b_formato_del_paquete(entorno):
    """El paquete respeta los campos y tamaños del Anexo B."""
    p = enviar(entorno)
    assert set(p) == {"version", "metadatos", "efimera_pub", "nonce", "cifrado", "firma"}
    assert p["version"] == "buzon-seguro-v1"
    assert set(p["metadatos"]) == {"remitente", "destinatario", "fecha", "archivo"}
    assert len(almacen.desde_b64(p["efimera_pub"])) == 32
    assert len(almacen.desde_b64(p["nonce"])) == 12
    assert len(almacen.desde_b64(p["firma"])) == 64

def test_bitacora_registra_envios_y_recepciones(entorno):
    """RF7: cada envío y recepción queda en la bitácora con el mismo identificador."""
    p = enviar(entorno)
    paquete.descifrar(p, BETO, entorno.claves[BETO])
    eventos = [json.loads(l) for l in almacen.ruta_bitacora().read_text(encoding="utf-8").splitlines()]
    envio = next(e for e in eventos if e["evento"] == "ENVIO")
    recepcion = next(e for e in eventos if e["evento"] == "RECEPCION")
    assert envio["paquete"] == recepcion["paquete"]

def test_nombre_de_archivo_malicioso_no_sale_de_recibidos(entorno, tmp_path):
    """Un nombre como '../../x' en los metadatos no permite escribir fuera de la carpeta."""
    destino = paquete.guardar_recibido(BETO, {"archivo": "../../fuera.txt"}, b"x", tmp_path / "rec")
    assert destino.parent == tmp_path / "rec"
    assert destino.name == "fuera.txt"

def test_remitente_con_ruta_maliciosa_se_rechaza(entorno):
    """Un remitente como '../usuarios/beto' en un paquete manipulado se rechaza."""
    p = enviar(entorno)
    p["metadatos"]["remitente"] = "../usuarios/beto.martinez"
    with pytest.raises(PaqueteRechazado):
        paquete.descifrar(p, BETO, entorno.claves[BETO])