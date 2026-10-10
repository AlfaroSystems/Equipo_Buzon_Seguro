"""
RF7: bitácora encadenada con hashes (la misma idea de una cadena de bloques, Semana 9).

Cada línea es un JSON con los datos del evento, más:
    - "hash_anterior": el hash de la línea anterior (64 ceros en la primera);
    - "hash": SHA-256 de todos los demás campos de la línea, incluido hash_anterior.

Si alguien edita una línea, su "hash" deja de coincidir. Si además recalcula ese
hash, se rompe el enlace con la línea siguiente. El comando auditar recorre la
cadena y señala la primera línea alterada.

Limitación: quien reescriba la bitácora completa desde la línea alterada hasta
el final no se detecta solo con la cadena. Por eso auditar muestra el "hash final",
que conviene anotar fuera del sistema (por ejemplo, en un acta o en un correo)
para compararlo en la siguiente auditoría.
"""
import hashlib
import json

from . import almacen

HASH_INICIAL = "0" * 64  # "hash anterior" de la primera línea

def _hash_entrada(entrada: dict) -> str:
    """SHA-256 de la forma canónica de la entrada, sin su propio campo "hash"."""
    sin_hash = {k: v for k, v in entrada.items() if k != "hash"}
    canonica = json.dumps(sin_hash, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonica.encode("utf-8")).hexdigest()

def _ultimo_hash(ruta) -> str:
    """Hash de la última línea (o HASH_INICIAL si la bitácora está vacía)."""
    if not ruta.exists():
        return HASH_INICIAL
    ultima = None
    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            if linea.strip():
                ultima = linea
    if ultima is None:
        return HASH_INICIAL
    try:
        return json.loads(ultima)["hash"]
    except (ValueError, KeyError, TypeError):
        # La última línea está dañada. Igual se encadena con el hash del texto
        # crudo y auditar señalará la línea dañada.
        return hashlib.sha256(ultima.encode("utf-8")).hexdigest()

def registrar(evento: str, **detalles) -> dict:
    """Agrega un evento al final de la bitácora, encadenado con el anterior."""
    ruta = almacen.ruta_bitacora()
    ruta.parent.mkdir(parents=True, exist_ok=True)
    entrada = {"fecha": almacen.ahora_iso(), "evento": evento, **detalles}
    entrada["hash_anterior"] = _ultimo_hash(ruta)
    entrada["hash"] = _hash_entrada(entrada)
    with open(ruta, "a", encoding="utf-8") as f:
        f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
    return entrada

def auditar() -> dict:
    """RF7: verifica la cadena completa.

    Devuelve un diccionario con:
        integra (bool), linea_alterada (número de línea o None),
        lineas (cuántas se revisaron) y hash_final (hash de la última línea válida).
    """
    ruta = almacen.ruta_bitacora()
    resultado = {"integra": True, "linea_alterada": None, "lineas": 0, "hash_final": HASH_INICIAL}
    if not ruta.exists():
        return resultado

    esperado = HASH_INICIAL
    with open(ruta, encoding="utf-8") as f:
        for numero, linea in enumerate(f, start=1):
            if not linea.strip():
                continue
            resultado["lineas"] += 1
            try:
                entrada = json.loads(linea)
                valida = (
                    entrada["hash_anterior"] == esperado          # ¿sigue la cadena?
                    and entrada["hash"] == _hash_entrada(entrada)  # ¿su contenido es el original?
                )
            except (ValueError, KeyError, TypeError, AttributeError):
                valida = False
            if not valida:
                resultado.update(integra=False, linea_alterada=numero)
                return resultado
            esperado = entrada["hash"]
    resultado["hash_final"] = esperado
    return resultado
