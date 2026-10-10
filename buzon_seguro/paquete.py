"""
RF3 a RF6: construir, firmar, verificar y abrir paquetes .buzon (formato del Anexo B).

ENVÍO (cifrar_para)
1. Se genera un par X25519 EFÍMERO, nuevo para cada documento.
2. ECDH(efímera privada, X25519 pública del destinatario) -> secreto compartido.
3. HKDF-SHA256(secreto, info=b"buzon-seguro-v1") -> clave AES de 256 bits.
4. AES-256-GCM(clave, nonce aleatorio de 12 bytes, contenido, AAD = metadatos).
5. Ed25519 del remitente firma: efimera_pub || nonce || metadatos || cifrado.
6. La clave efímera privada nunca se guarda: al terminar la función se pierde.

RECEPCIÓN (descifrar = verificar_paquete + abrir_paquete)
1. Formato correcto (si no, rechazo genérico).
2. La clave del remitente está verificada y no cambió (RF2 / P5).
3. Se verifica la FIRMA. Solo si es válida se continúa (RF5).
4. Se abre la clave privada del destinatario (contraseña) y se descifra con GCM.
5. Se compara el SHA-256 del documento con el que venía dentro (RF6).
"""
import hashlib
import hmac
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import almacen, bitacora, identidad
from .errores import ErrorBuzon, PaqueteRechazado

VERSION = "buzon-seguro-v1"
INFO_HKDF = b"buzon-seguro-v1"
CAMPOS_METADATOS = ("archivo", "destinatario", "fecha", "remitente")  # en orden alfabético

# ─── Piezas criptográficas ──────────────────────────────────────────────────
def serializar_metadatos(metadatos: dict) -> bytes:
    """Única forma (canónica) de convertir los metadatos en bytes.

    Se usa igual al firmar, al verificar y como AAD de AES-GCM. Si cada lado
    serializara distinto (otro orden de claves u otros espacios), ni la firma
    ni la etiqueta GCM coincidirían.
    """
    return json.dumps(
        metadatos, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")

def derivar_clave(secreto_ecdh: bytes) -> bytes:
    """HKDF-SHA256: convierte el secreto ECDH en una clave AES-256 uniforme.

    El secreto de X25519 no es una cadena aleatoria uniforme y no debe usarse
    directamente como clave. HKDF lo convierte en una clave uniforme, y el
    parámetro info la liga a este protocolo y a esta versión.
    """
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO_HKDF).derive(
        secreto_ecdh
    )

def _mensaje_a_firmar(efimera_pub: bytes, nonce: bytes, aad: bytes, cifrado: bytes) -> bytes:
    """Lo que firma Ed25519 según el Anexo B: efimera_pub || nonce || metadatos || cifrado."""
    return efimera_pub + nonce + aad + cifrado


def identificador(firma: bytes) -> str:
    """Identificador corto del paquete para la bitácora: SHA-256 de su firma.

    Cada firma es única, así que identifica al paquete sin revelar su contenido.
    """
    return hashlib.sha256(firma).hexdigest()[:16]

# ─── RF3, RF4 y RF6 · Construir el paquete ──────────────────────────────────
def construir_paquete(datos: bytes, metadatos: dict, x25519_pub_destinatario: bytes,
                        clave_firma: ed25519.Ed25519PrivateKey) -> dict:
    """Cifra `datos` para el destinatario y firma el paquete (formato del Anexo B)."""
    # RF6: el hash del original viaja DENTRO del contenido cifrado.
    contenido = json.dumps({
        "sha256_original": hashlib.sha256(datos).hexdigest(),
        "datos": almacen.b64(datos),
    }).encode("utf-8")
    aad = serializar_metadatos(metadatos)

    # RF3: ECDH con un par efímero (nuevo en cada envío, ver P8). Robar después
    # la clave fija del remitente no sirve para recalcular la clave de este paquete.
    efimera = x25519.X25519PrivateKey.generate()
    efimera_pub = efimera.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    destinatario = x25519.X25519PublicKey.from_public_bytes(x25519_pub_destinatario)
    clave = derivar_clave(efimera.exchange(destinatario))

    # Nonce de 96 bits del generador seguro del sistema. Nunca se reutiliza con
    # la misma clave (además, cada paquete tiene una clave distinta).
    nonce = os.urandom(12)
    # AES-256-GCM devuelve el texto cifrado más la etiqueta de 16 bytes. El AAD
    # (metadatos) no se cifra, pero queda autenticado: si cambia, el descifrado falla.
    cifrado = AESGCM(clave).encrypt(nonce, contenido, aad)

    # RF4: el remitente firma todo lo que viaja.
    firma = clave_firma.sign(_mensaje_a_firmar(efimera_pub, nonce, aad, cifrado))

    return {
        "version": VERSION,
        "metadatos": metadatos,
        "efimera_pub": almacen.b64(efimera_pub),
        "nonce": almacen.b64(nonce),
        "cifrado": almacen.b64(cifrado),
        "firma": almacen.b64(firma),
    }

def cifrar_para(ruta_archivo: str, remitente: str, destinatario: str, contrasena: bytes) -> dict:
    """RF3 y RF4: cifra un archivo para un destinatario VERIFICADO y lo firma."""
    almacen.validar_usuario(remitente)
    # RF2: no se cifra para alguien cuya huella no se verificó (o que cambió).
    publicas_destino = identidad.exigir_verificada(remitente, destinatario)

    ruta = Path(ruta_archivo)
    if not ruta.is_file():
        raise ErrorBuzon(f"No se encontró el archivo: {ruta_archivo}")
    clave_firma = identidad.cargar_privada_firma(remitente, contrasena)

    metadatos = {
        "remitente": remitente,
        "destinatario": destinatario,
        "fecha": almacen.ahora_iso(),
        "archivo": ruta.name,
    }
    paquete = construir_paquete(ruta.read_bytes(), metadatos, publicas_destino["x25519"], clave_firma)
    bitacora.registrar("ENVIO", remitente=remitente, destinatario=destinatario,
                        archivo=ruta.name, paquete=identificador(almacen.desde_b64(paquete["firma"])))
    return paquete

# ─── RF5 y RF6 · Verificar y abrir el paquete ───────────────────────────────
def leer_campos(paquete: dict) -> dict:
    """Valida la estructura del paquete y decodifica sus campos binarios.
    Un problema de formato recibe el mismo rechazo genérico que una firma inválida.
    """
    try:
        if paquete["version"] != VERSION:
            raise ValueError("versión")
        metadatos = paquete["metadatos"]
        if (not isinstance(metadatos, dict)
                or sorted(metadatos) != list(CAMPOS_METADATOS)
                or not all(isinstance(v, str) for v in metadatos.values())):
            raise ValueError("metadatos")
        campos = {
            "metadatos": metadatos,
            "aad": serializar_metadatos(metadatos),
            "efimera_pub": almacen.desde_b64(paquete["efimera_pub"]),
            "nonce": almacen.desde_b64(paquete["nonce"]),
            "cifrado": almacen.desde_b64(paquete["cifrado"]),
            "firma": almacen.desde_b64(paquete["firma"]),
        }
        if (len(campos["efimera_pub"]) != 32 or len(campos["nonce"]) != 12
                or len(campos["firma"]) != 64 or len(campos["cifrado"]) < 16):
            raise ValueError("longitudes")
        return campos
    except (KeyError, TypeError, ValueError):  # binascii.Error es un ValueError
        raise PaqueteRechazado() from None

def verificar_firma(campos: dict, ed25519_pub_remitente: bytes) -> None:
    """Comprueba la firma Ed25519 del remitente. Lanza InvalidSignature si no es válida."""
    clave = ed25519.Ed25519PublicKey.from_public_bytes(ed25519_pub_remitente)
    clave.verify(
        campos["firma"],
        _mensaje_a_firmar(campos["efimera_pub"], campos["nonce"], campos["aad"], campos["cifrado"]),
    )

def abrir_contenido(campos: dict, clave_cifrado: x25519.X25519PrivateKey) -> tuple[bytes, str]:
    """Deriva la clave, descifra con AES-GCM y comprueba el SHA-256 del original (RF6).

    Lanza InvalidTag si la clave no es la correcta (otro destinatario, P4) o si
    el cifrado o los metadatos (AAD) fueron alterados (P2, P3).
    Devuelve (datos, sha256_hex).
    """
    efimera = x25519.X25519PublicKey.from_public_bytes(campos["efimera_pub"])
    clave = derivar_clave(clave_cifrado.exchange(efimera))
    contenido = json.loads(AESGCM(clave).decrypt(campos["nonce"], campos["cifrado"], campos["aad"]))
    datos = almacen.desde_b64(contenido["datos"])
    sha256 = hashlib.sha256(datos).hexdigest()
    if not hmac.compare_digest(sha256, contenido["sha256_original"]):
        raise ValueError("el SHA-256 del documento no coincide")
    return datos, sha256

def _rechazo(destinatario: str, remitente=None, firma=None) -> PaqueteRechazado:
    """Registra el rechazo en la bitácora y devuelve el error genérico para lanzarlo."""
    bitacora.registrar("RECHAZO", destinatario=destinatario, remitente=str(remitente),
                        paquete=identificador(firma) if firma else None)
    return PaqueteRechazado()

def verificar_paquete(paquete: dict, destinatario: str) -> dict:
    """RF5, primera parte: formato, confianza en el remitente y FIRMA.

    No necesita la contraseña del destinatario: nada se descifra hasta que la
    firma se comprueba. Devuelve los campos listos para abrir_paquete().
    """
    almacen.validar_usuario(destinatario)
    try:
        campos = leer_campos(paquete)
        remitente = almacen.validar_usuario(campos["metadatos"]["remitente"])
    except ErrorBuzon:
        raise _rechazo(destinatario) from None

    # RF2 y P5: la clave del remitente debe ser la misma que se verificó por otro canal.
    try:
        publicas_remitente = identidad.exigir_verificada(destinatario, remitente)
    except ErrorBuzon:
        bitacora.registrar("ALERTA_CLAVE", destinatario=destinatario, remitente=remitente,
                            paquete=identificador(campos["firma"]))
        raise

    try:
        verificar_firma(campos, publicas_remitente["ed25519"])
    except InvalidSignature:
        raise _rechazo(destinatario, remitente, campos["firma"]) from None
    return campos

def abrir_paquete(campos: dict, destinatario: str, contrasena: bytes) -> dict:
    """RF5, segunda parte, y RF6: descifra un paquete cuya firma ya fue verificada.

    No se compara el nombre del destinatario: la protección real es criptográfica.
    Solo quien tiene la clave privada X25519 correcta puede derivar la clave AES (P4).
    """
    metadatos = campos["metadatos"]
    clave_cifrado = identidad.cargar_privada_cifrado(destinatario, contrasena)
    try:
        datos, sha256 = abrir_contenido(campos, clave_cifrado)
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise _rechazo(destinatario, metadatos["remitente"], campos["firma"]) from None

    bitacora.registrar("RECEPCION", remitente=metadatos["remitente"], destinatario=destinatario,
                        archivo=metadatos["archivo"], paquete=identificador(campos["firma"]))
    return {"datos": datos, "sha256": sha256, "metadatos": metadatos}

def descifrar(paquete: dict, destinatario: str, contrasena: bytes) -> dict:
    """RF5: verifica la firma ANTES de descifrar. Si algo falla, rechaza sin revelar detalles.

    Devuelve {"datos": bytes, "sha256": str, "metadatos": dict}.
    """
    campos = verificar_paquete(paquete, destinatario)
    return abrir_paquete(campos, destinatario, contrasena)

# ─── Archivos .buzon ────────────────────────────────────────────────────────
def guardar_paquete(paquete: dict, ruta: Path) -> None:
    """Guarda el paquete como JSON (extensión .buzon)."""
    almacen.escribir_json(Path(ruta), paquete)

def leer_paquete(ruta: Path) -> dict:
    """Lee un archivo .buzon. Si no es JSON válido, rechazo genérico."""
    try:
        return almacen.leer_json(Path(ruta))
    except FileNotFoundError:
        raise ErrorBuzon(f"No se encontró el paquete: {ruta}") from None
    except (ValueError, UnicodeDecodeError):
        raise PaqueteRechazado() from None

def guardar_recibido(usuario: str, metadatos: dict, datos: bytes, carpeta=None) -> Path:
    """Guarda el documento descifrado sin sobrescribir archivos existentes."""
    carpeta = Path(carpeta) if carpeta else almacen.carpeta_usuario(usuario) / "recibidos"
    carpeta.mkdir(parents=True, exist_ok=True)
    destino = almacen.ruta_sin_conflicto(carpeta, almacen.nombre_archivo_seguro(metadatos["archivo"]))
    destino.write_bytes(datos)
    return destino