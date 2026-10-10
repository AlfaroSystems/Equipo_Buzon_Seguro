"""
Rutas de archivos, lectura y escritura de JSON y validación de nombres.

Estructura de la carpeta de datos (por defecto ./datos):

    datos/
    ├── directorio/              Carpeta compartida (canal NO confiable)
    │   └── <usuario>.json       claves públicas de cada usuario
    ├── usuarios/<usuario>/      Carpeta privada de cada usuario ("su computadora")
    │   ├── x25519_privada.pem   clave de cifrado, PKCS#8 cifrado con contraseña
    │   ├── ed25519_privada.pem  clave de firma, PKCS#8 cifrado con contraseña
    │   ├── confianza.json       huellas que el usuario verificó por otro canal
    │   └── recibidos/           documentos descifrados
    └── bitacora.jsonl           bitácora encadenada de eventos (RF7)

La carpeta se puede cambiar con la variable de entorno BUZON_DATOS. Las pruebas
automatizadas la usan para trabajar en una carpeta temporal.
"""
import base64
import json
import os
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from .errores import ErrorBuzon

# Nombres de usuario permitidos: minúsculas, números, punto, guion y guion bajo.
# Validarlos impide que un nombre como "../../x" (por ejemplo, dentro de un
# paquete manipulado) haga leer o escribir archivos fuera de la carpeta de datos.
_PATRON_USUARIO = re.compile(r"[a-z0-9][a-z0-9._-]{2,31}")

# Caracteres prohibidos en nombres de archivo de Windows (incluye ":" para evitar
# flujos alternativos de NTFS) y caracteres de control.
_CARACTERES_PROHIBIDOS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

def ruta_datos() -> Path:
    """Carpeta raíz de datos (variable BUZON_DATOS o ./datos)."""
    return Path(os.environ.get("BUZON_DATOS", "datos"))

def carpeta_directorio() -> Path:
    """Carpeta compartida donde se publican las claves públicas."""
    return ruta_datos() / "directorio"

def carpeta_usuario(usuario: str) -> Path:
    """Carpeta privada de un usuario."""
    return ruta_datos() / "usuarios" / validar_usuario(usuario)

def ruta_bitacora() -> Path:
    """Archivo de la bitácora encadenada."""
    return ruta_datos() / "bitacora.jsonl"

def validar_usuario(nombre: str) -> str:
    """Devuelve el nombre si es válido; si no, lanza ErrorBuzon."""
    if not isinstance(nombre, str) or not _PATRON_USUARIO.fullmatch(nombre):
        raise ErrorBuzon(
            f"Nombre de usuario no válido: {nombre!r}. Use de 3 a 32 caracteres: "
            "minúsculas, números, punto, guion o guion bajo (ej.: ana.lopez)."
        )
    return nombre

def b64(datos: bytes) -> str:
    """Codifica bytes en Base64 (texto)."""
    return base64.b64encode(datos).decode("ascii")

def desde_b64(texto: str) -> bytes:
    """Decodifica Base64. validate=True rechaza caracteres inválidos en vez de ignorarlos."""
    return base64.b64decode(texto, validate=True)

def ahora_iso() -> str:
    """Fecha y hora local con zona horaria, ej.: 2026-10-20T14:35:00-06:00."""
    return datetime.now().astimezone().isoformat(timespec="seconds")

def leer_json(ruta: Path):
    """Lee un archivo JSON en UTF-8 (igual en Windows, macOS y Linux)."""
    with open(ruta, encoding="utf-8") as f:
        return json.load(f)

def escribir_json(ruta: Path, datos) -> None:
    """Escribe un archivo JSON en UTF-8, creando las carpetas necesarias."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)

def nombre_archivo_seguro(nombre: str) -> str:
    """Limpia el nombre de archivo que viene en los metadatos de un paquete.

    Se queda solo con la última parte de la ruta y reemplaza los caracteres
    peligrosos. Así un remitente no puede escribir fuera de la carpeta de
    recibidos con nombres como "../../config.txt".
    """
    nombre = PurePosixPath(str(nombre).replace("\\", "/")).name
    nombre = _CARACTERES_PROHIBIDOS.sub("_", nombre).strip(" .")
    return nombre or "documento_recibido"

def ruta_sin_conflicto(carpeta: Path, nombre: str) -> Path:
    """Ruta dentro de `carpeta` que no sobrescribe un archivo existente."""
    destino = carpeta / nombre
    contador = 1
    while destino.exists():
        destino = carpeta / f"{Path(nombre).stem}_{contador}{Path(nombre).suffix}"
        contador += 1
    return destino