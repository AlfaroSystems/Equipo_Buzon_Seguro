"""
Herramienta de DEMOSTRACIÓN de ataques contra NUESTRO PROPIO Buzón Seguro.

Sirve para mostrar en la defensa los escenarios P2, P3, P5, P7 y P8 sin editar
archivos a mano. Uso ético (apartado 11 de la tarea): solo contra el sistema del equipo.
    python atacante.py alterar-byte --paquete solicitud.buzon                       (P2)
    python atacante.py cambiar-metadato --paquete solicitud.buzon --campo fecha --valor 2026-01-01T00:00:00-06:00 (P3)
    python atacante.py suplantar --mallory mallory --victima ana.lopez --para beto.martinez --archivo orden.txt (P5)
    python atacante.py restaurar --victima ana.lopez                  (deshace P5)
    python atacante.py alterar-bitacora --linea 3                                   (P7)
    python atacante.py comparar primero.buzon segundo.buzon                         (P8)
"""
import argparse
import getpass
import json
import shutil
import sys
from pathlib import Path

from buzon_seguro import almacen, identidad, paquete
from buzon_seguro.errores import ErrorBuzon

def _copia(ruta: Path, sufijo: str) -> Path:
    """Ruta de la copia manipulada, sin tocar el paquete original."""
    return ruta.with_name(f"{ruta.stem}_{sufijo}{ruta.suffix}")

def alterar_byte(args) -> None:
    """P2: invierte un bit de UN byte del texto cifrado."""
    ruta = Path(args.paquete)
    p = paquete.leer_paquete(ruta)
    cifrado = bytearray(almacen.desde_b64(p["cifrado"]))
    pos = args.posicion if args.posicion is not None else len(cifrado) // 2
    antes = cifrado[pos]
    cifrado[pos] ^= 0x01
    p["cifrado"] = almacen.b64(bytes(cifrado))
    salida = _copia(ruta, "alterado")
    paquete.guardar_paquete(p, salida)
    print(f"[Atacante] Byte {pos} del cifrado: {antes:02x} -> {cifrado[pos]:02x}")
    print(f"[Atacante] Paquete manipulado guardado en {salida}")

def cambiar_metadato(args) -> None:
    """P3: cambia el destinatario, la fecha u otro metadato."""
    ruta = Path(args.paquete)
    p = paquete.leer_paquete(ruta)
    antes = p["metadatos"].get(args.campo)
    p["metadatos"][args.campo] = args.valor
    salida = _copia(ruta, "metadatos")
    paquete.guardar_paquete(p, salida)
    print(f"[Atacante] metadatos.{args.campo}: {antes!r} -> {args.valor!r}")
    print(f"[Atacante] Paquete manipulado guardado en {salida}")

def suplantar(args) -> None:
    """P5: Mallory pone SUS claves públicas en el archivo de la víctima y envía "como" ella."""
    carpeta = almacen.carpeta_directorio()
    original = carpeta / f"{almacen.validar_usuario(args.victima)}.json"
    respaldo = original.with_name(original.name + ".bak")
    if not respaldo.exists():
        shutil.copy2(original, respaldo)
    falsas = almacen.leer_json(carpeta / f"{almacen.validar_usuario(args.mallory)}.json")
    falsas["usuario"] = args.victima
    almacen.escribir_json(original, falsas)
    print(f"[Atacante] Reemplacé en el directorio la clave de {args.victima} por la de {args.mallory}.")

    contrasena = getpass.getpass(f"Contraseña de {args.mallory}: ").encode("utf-8")
    clave_firma = identidad.cargar_privada_firma(args.mallory, contrasena)
    archivo = Path(args.archivo)
    metadatos = {"remitente": args.victima, "destinatario": args.para, "fecha": almacen.ahora_iso(), "archivo": archivo.name}
    falso = paquete.construir_paquete(archivo.read_bytes(), metadatos, identidad.cargar_publicas(args.para)["x25519"], clave_firma)
    salida = Path(args.salida or f"{archivo.name}.buzon")
    paquete.guardar_paquete(falso, salida)
    print(f"[Atacante] Paquete \"de {args.victima}\" firmado por {args.mallory} guardado en {salida}")
    print(f"[Atacante] Para deshacerlo: python atacante.py restaurar --victima {args.victima}")

def restaurar(args) -> None:
    """Deshace P5: devuelve al directorio la clave pública original de la víctima."""
    original = almacen.carpeta_directorio() / f"{almacen.validar_usuario(args.victima)}.json"
    respaldo = original.with_name(original.name + ".bak")
    if not respaldo.exists():
        raise ErrorBuzon("No hay respaldo que restaurar.")
    shutil.move(respaldo, original)
    print(f"[OK] Clave pública original de {args.victima} restaurada.")

def alterar_bitacora(args) -> None:
    """P7: cambia la fecha de una línea de la bitácora, como lo haría un empleado deshonesto."""
    ruta = almacen.ruta_bitacora()
    lineas = ruta.read_text(encoding="utf-8").splitlines()
    if not 1 <= args.linea <= len(lineas):
        raise ErrorBuzon(f"La bitácora tiene {len(lineas)} líneas.")
    entrada = json.loads(lineas[args.linea - 1])
    antes = entrada.get(args.campo)
    entrada[args.campo] = args.valor
    lineas[args.linea - 1] = json.dumps(entrada, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print(f"[Atacante] Línea {args.linea}, campo {args.campo}: {antes!r} -> {args.valor!r}")

def comparar(args) -> None:
    """P8: compara dos paquetes del mismo documento campo por campo."""
    a, b = paquete.leer_paquete(args.primero), paquete.leer_paquete(args.segundo)
    for campo in ("efimera_pub", "nonce", "cifrado", "firma"):
        estado = "IGUAL" if a[campo] == b[campo] else "distinto"
        print(f"  {campo:<12} {estado:<9} {a[campo][:24]}...  vs  {b[campo][:24]}...")

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="atacante.py", description="Demostración de ataques (solo contra nuestro sistema).")
    sub = p.add_subparsers(dest="accion", required=True, metavar="accion")

    s = sub.add_parser("alterar-byte", help="P2: modificar un byte del cifrado")
    s.add_argument("--paquete", required=True)
    s.add_argument("--posicion", type=int)
    s.set_defaults(funcion=alterar_byte)

    s = sub.add_parser("cambiar-metadato", help="P3: cambiar destinatario o fecha")
    s.add_argument("--paquete", required=True)
    s.add_argument("--campo", required=True, choices=["remitente", "destinatario", "fecha", "archivo"])
    s.add_argument("--valor", required=True)
    s.set_defaults(funcion=cambiar_metadato)

    s = sub.add_parser("suplantar", help="P5: Mallory reemplaza la clave de la víctima y envía como ella")
    s.add_argument("--mallory", required=True)
    s.add_argument("--victima", required=True)
    s.add_argument("--para", required=True)
    s.add_argument("--archivo", required=True)
    s.add_argument("--salida")
    s.set_defaults(funcion=suplantar)

    s = sub.add_parser("restaurar", help="deshacer P5")
    s.add_argument("--victima", required=True)
    s.set_defaults(funcion=restaurar)

    s = sub.add_parser("alterar-bitacora", help="P7: editar una línea de la bitácora")
    s.add_argument("--linea", required=True, type=int)
    s.add_argument("--campo", default="fecha")
    s.add_argument("--valor", default="2020-01-01T00:00:00-06:00")
    s.set_defaults(funcion=alterar_bitacora)

    s = sub.add_parser("comparar", help="P8: comparar dos paquetes")
    s.add_argument("primero")
    s.add_argument("segundo")
    s.set_defaults(funcion=comparar)

    args = p.parse_args(argv)
    try:
        args.funcion(args)
        return 0
    except (ErrorBuzon, OSError, KeyError, ValueError) as e:
        print(f"[X] {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())