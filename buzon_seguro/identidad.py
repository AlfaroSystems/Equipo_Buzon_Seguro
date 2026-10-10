"""
RF1 (generar identidad) y RF2 (huellas y verificación de claves públicas).
Cada usuario tiene dos pares de claves de curva elíptica (Semana 11):
    - X25519, para acordar claves (ECDH) y que le puedan cifrar documentos.
    - Ed25519, para firmar lo que envía.
Se usan pares distintos porque es buena práctica no mezclar el uso de cifrado
con el de firma en una misma clave.
"""
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from . import almacen, bitacora
from .errores import ClaveNoConfiable, ContrasenaIncorrecta, ErrorBuzon

# PKCS#8 con BestAvailableEncryption deriva la clave con PBKDF2-SHA256 de solo
# 2,048 iteraciones (lo comprobamos con "openssl asn1parse"). Para compensar,
# exigimos contraseñas largas (recuerden el caso LastPass de la Semana 8).
LONGITUD_MINIMA_CONTRASENA = 12

ARCHIVO_X25519 = "x25519_privada.pem"
ARCHIVO_ED25519 = "ed25519_privada.pem"

# ─── RF1 · Generar identidad ────────────────────────────────────────────────
def generar_identidad(nombre: str, contrasena: bytes) -> None:
    """RF1: crea un par X25519 (cifrado) y un par Ed25519 (firma).

    Las claves privadas se guardan en formato PKCS#8 cifradas con la
    contraseña (BestAvailableEncryption). Las públicas se publican en el
    directorio compartido.
    """
    almacen.validar_usuario(nombre)
    if len(contrasena) < LONGITUD_MINIMA_CONTRASENA:
        raise ErrorBuzon(
            f"La contraseña debe tener al menos {LONGITUD_MINIMA_CONTRASENA} caracteres."
        )
    carpeta = almacen.carpeta_usuario(nombre)
    if (carpeta / ARCHIVO_X25519).exists() or (carpeta / ARCHIVO_ED25519).exists():
        raise ErrorBuzon(f"Ya existe una identidad para {nombre}; no se sobrescribe.")

    # generate() usa el generador aleatorio criptográficamente seguro del sistema.
    priv_cifrado = x25519.X25519PrivateKey.generate()
    priv_firma = ed25519.Ed25519PrivateKey.generate()

    proteccion = serialization.BestAvailableEncryption(contrasena)
    carpeta.mkdir(parents=True, exist_ok=True)
    for archivo, clave in ((ARCHIVO_X25519, priv_cifrado), (ARCHIVO_ED25519, priv_firma)):
        pem = clave.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=proteccion,
        )
        ruta = carpeta / archivo
        ruta.write_bytes(pem)
        os.chmod(ruta, 0o600)  # solo el dueño puede leerla (efecto completo en Linux/macOS)

    publicas = {
        "usuario": nombre,
        "x25519_pub": almacen.b64(_bytes_publicos(priv_cifrado.public_key())),
        "ed25519_pub": almacen.b64(_bytes_publicos(priv_firma.public_key())),
    }
    almacen.escribir_json(almacen.carpeta_directorio() / f"{nombre}.json", publicas)
    bitacora.registrar("IDENTIDAD", usuario=nombre)

    # Cada usuario confía en su propia clave desde el inicio.
    marcar_verificada(nombre, nombre)

def _bytes_publicos(clave_publica) -> bytes:
    """Los 32 bytes "crudos" de una clave pública X25519 o Ed25519."""
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

def _cargar_privada(usuario: str, archivo: str, tipo_esperado, contrasena: bytes):
    """Abre una clave privada cifrada. Cualquier fallo da el mismo error (P6)."""
    ruta = almacen.carpeta_usuario(usuario) / archivo
    if not ruta.exists():
        raise ErrorBuzon(f"No existe una identidad local para {usuario}.")
    try:
        clave = serialization.load_pem_private_key(ruta.read_bytes(), password=contrasena)
    except (ValueError, TypeError):
        # "from None" oculta el error interno: no se revela si la contraseña
        # era incorrecta o si el archivo estaba dañado.
        raise ContrasenaIncorrecta() from None
    if not isinstance(clave, tipo_esperado):
        raise ContrasenaIncorrecta()
    return clave

def cargar_privada_cifrado(usuario: str, contrasena: bytes) -> x25519.X25519PrivateKey:
    """Clave privada X25519 del usuario (para descifrar lo que recibe)."""
    return _cargar_privada(usuario, ARCHIVO_X25519, x25519.X25519PrivateKey, contrasena)

def cargar_privada_firma(usuario: str, contrasena: bytes) -> ed25519.Ed25519PrivateKey:
    """Clave privada Ed25519 del usuario (para firmar lo que envía)."""
    return _cargar_privada(usuario, ARCHIVO_ED25519, ed25519.Ed25519PrivateKey, contrasena)

def cargar_publicas(usuario: str) -> dict:
    """Lee del directorio compartido las claves públicas de un usuario.

    Ojo: el directorio NO es confiable. Antes de usar estas claves hay que
    comprobar la huella con exigir_verificada().
    """
    ruta = almacen.carpeta_directorio() / f"{almacen.validar_usuario(usuario)}.json"
    if not ruta.exists():
        raise ErrorBuzon(f"No hay claves públicas de {usuario} en el directorio.")
    try:
        datos = almacen.leer_json(ruta)
        publicas = {
            "x25519": almacen.desde_b64(datos["x25519_pub"]),
            "ed25519": almacen.desde_b64(datos["ed25519_pub"]),
        }
    except (ValueError, KeyError, TypeError):
        raise ErrorBuzon(f"El archivo de claves públicas de {usuario} está dañado.") from None
    if len(publicas["x25519"]) != 32 or len(publicas["ed25519"]) != 32:
        raise ErrorBuzon(f"El archivo de claves públicas de {usuario} está dañado.")
    return publicas

# ─── RF2 · Huellas y verificación ───────────────────────────────────────────
def huella(clave_publica_bytes: bytes) -> str:
    """RF2: huella SHA-256 para compararla por un segundo canal.

    Se muestra en grupos de 4 caracteres hexadecimales para que sea fácil
    dictarla por teléfono o leerla en persona.
    """
    h = hashlib.sha256(clave_publica_bytes).hexdigest().upper()
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))

def huella_de_publicas(publicas: dict) -> str:
    """Huella de la identidad completa: SHA-256(clave X25519 || clave Ed25519).

    Ambas claves miden 32 bytes, así que la concatenación no es ambigua. Con una
    sola huella se protegen las dos: si Mallory cambia cualquiera, la huella cambia.
    """
    return huella(publicas["x25519"] + publicas["ed25519"])

def huella_usuario(usuario: str) -> str:
    """Huella de las claves públicas que el directorio tiene AHORA para `usuario`."""
    return huella_de_publicas(cargar_publicas(usuario))

def _ruta_confianza(usuario: str):
    return almacen.carpeta_usuario(usuario) / "confianza.json"

def _leer_confianza(usuario: str) -> dict:
    ruta = _ruta_confianza(usuario)
    return almacen.leer_json(ruta) if ruta.exists() else {}

def marcar_verificada(usuario: str, contacto: str) -> str:
    """Guarda en la carpeta privada de `usuario` la huella actual de `contacto`.

    Solo debe hacerse DESPUÉS de comparar la huella por un segundo canal
    (en persona o por teléfono), como en Signal o SSH. Devuelve la huella guardada.
    """
    almacen.validar_usuario(usuario)
    h = huella_usuario(contacto)
    confianza = _leer_confianza(usuario)
    confianza[contacto] = {"huella": h, "verificada": almacen.ahora_iso()}
    almacen.escribir_json(_ruta_confianza(usuario), confianza)
    if usuario != contacto:
        bitacora.registrar("VERIFICACION", usuario=usuario, contacto=contacto)
    return h

def exigir_verificada(usuario: str, contacto: str) -> dict:
    """Devuelve las claves públicas de `contacto` solo si `usuario` las verificó.

    Compara la huella ACTUAL del directorio con la que se guardó al verificar.
    Si alguien reemplazó la clave en la carpeta compartida (escenario P5), las
    huellas no coinciden y la operación se detiene.
    """
    registro = _leer_confianza(usuario).get(contacto)
    if registro is None:
        raise ClaveNoConfiable(
            f"{contacto} no está verificado. Compare su huella por un segundo canal "
            f"y luego ejecute: python buzon.py verificar --usuario {usuario} --contacto {contacto}"
        )
    # Se leen las claves una sola vez y se devuelven esas mismas, para que no
    # puedan cambiar entre la comprobación y el uso.
    publicas = cargar_publicas(contacto)
    if not hmac.compare_digest(huella_de_publicas(publicas), registro["huella"]):
        raise ClaveNoConfiable(
            f"ALERTA: la clave pública de {contacto} en el directorio NO coincide con la "
            "que usted verificó. Posible suplantación (ataque de intermediario). "
            "No se continúa."
        )
    return publicas
