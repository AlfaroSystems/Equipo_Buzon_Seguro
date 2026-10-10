"""
Interfaz de línea de comandos del Buzón Seguro.

Este módulo solo se encarga de pedir datos y mostrar resultados. Toda la
criptografía está en identidad.py, paquete.py y bitacora.py.
"""
import argparse
import getpass
import sys
from pathlib import Path

from . import almacen, bitacora, identidad, paquete
from .errores import ErrorBuzon

def pedir_contrasena(usuario: str, confirmar: bool = False) -> bytes:
    """Pide la contraseña sin mostrarla en pantalla (getpass)."""
    contrasena = getpass.getpass(f"Contraseña de {usuario}: ")
    if confirmar and getpass.getpass("Repita la contraseña: ") != contrasena:
        raise ErrorBuzon("Las contraseñas no coinciden.")
    return contrasena.encode("utf-8")

# ─── Comandos ───────────────────────────────────────────────────────────────
def cmd_generar(args) -> None:
    print(f"Creando identidad para {args.usuario} "
        f"(contraseña de al menos {identidad.LONGITUD_MINIMA_CONTRASENA} caracteres).")
    identidad.generar_identidad(args.usuario, pedir_contrasena(args.usuario, confirmar=True))
    print(f"[OK] Claves privadas X25519 y Ed25519 guardadas cifradas en "
        f"{almacen.carpeta_usuario(args.usuario)}")
    print(f"[OK] Claves públicas publicadas en "
        f"{almacen.carpeta_directorio() / (args.usuario + '.json')}")
    print("\nHuella de su identidad (díctela a sus contactos por un segundo canal):")
    print(f"  {identidad.huella_usuario(args.usuario)}")

def cmd_huella(args) -> None:
    print(f"Huella SHA-256 de las claves públicas de {args.usuario} (según el directorio):")
    print(f"  {identidad.huella_usuario(args.usuario)}")

def cmd_verificar(args) -> None:
    h = identidad.huella_usuario(args.contacto)
    print(f"Huella de {args.contacto} según el directorio compartido:\n  {h}\n")
    print(f"Pídale a {args.contacto} que le lea su huella EN PERSONA o POR TELÉFONO")
    print("(nunca por el mismo canal por el que llegó la clave).")
    respuesta = input("¿Coinciden los 64 caracteres? Escriba SI para confirmar: ")
    if respuesta.strip().upper() != "SI":
        print("[!] No se marcó como verificada.")
        return
    identidad.marcar_verificada(args.usuario, args.contacto)
    print(f"[OK] {args.usuario} ahora confía en la clave de {args.contacto}.")

def cmd_cifrar(args) -> None:
    # Se revisa la confianza ANTES de pedir la contraseña, para no pedirla en vano.
    identidad.exigir_verificada(args.de, args.para)
    datos_paquete = paquete.cifrar_para(args.archivo, args.de, args.para, pedir_contrasena(args.de))
    salida = Path(args.salida) if args.salida else Path(f"{Path(args.archivo).name}.buzon")
    paquete.guardar_paquete(datos_paquete, salida)
    print(f"[OK] Documento cifrado para {args.para} y firmado por {args.de}.")
    print(f"[OK] Paquete guardado en: {salida}")

def cmd_descifrar(args) -> None:
    datos_paquete = paquete.leer_paquete(args.paquete)
    # 1) Primero se verifica la firma (no hace falta la contraseña todavía).
    campos = paquete.verificar_paquete(datos_paquete, args.usuario)
    remitente = campos["metadatos"]["remitente"]
    print(f"[OK] Firma de {remitente} válida (clave verificada por huella).")
    # 2) Solo entonces se abre la clave privada y se descifra.
    resultado = paquete.abrir_paquete(campos, args.usuario, pedir_contrasena(args.usuario))
    destino = paquete.guardar_recibido(args.usuario, resultado["metadatos"],
                                        resultado["datos"], args.salida)
    meta = resultado["metadatos"]
    print("[OK] Documento descifrado.")
    print(f"     Remitente:  {meta['remitente']}")
    print(f"     Fecha:      {meta['fecha']}")
    print(f"     Archivo:    {meta['archivo']}")
    print(f"[OK] Integridad: el SHA-256 coincide con el del original ({resultado['sha256']})")
    print(f"[OK] Guardado en: {destino}")

def cmd_auditar(args) -> int:
    r = bitacora.auditar()
    if r["integra"]:
        print(f"[OK] Bitácora íntegra: {r['lineas']} líneas verificadas.")
        print(f"     Hash final (anótelo fuera del sistema): {r['hash_final']}")
        return 0
    print(f"[X] ALERTA: la bitácora fue alterada. Primera línea alterada: {r['linea_alterada']}")
    return 2

# ─── Analizador de argumentos ───────────────────────────────────────────────
def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buzon.py",
        description="Buzón Seguro: intercambio de documentos cifrados y firmados.",
        epilog="Ejemplo: python buzon.py cifrar --de ana.lopez --para beto.martinez --archivo solicitud.pdf",
    )
    sub = p.add_subparsers(dest="accion", required=True, metavar="accion")

    s = sub.add_parser("generar", help="RF1: crear la identidad (claves) de un usuario")
    s.add_argument("--usuario", required=True)
    s.set_defaults(funcion=cmd_generar)

    s = sub.add_parser("huella", help="RF2: mostrar la huella SHA-256 de un usuario")
    s.add_argument("--usuario", required=True)
    s.set_defaults(funcion=cmd_huella)

    s = sub.add_parser("verificar", help="RF2: marcar como verificada la clave de un contacto")
    s.add_argument("--usuario", required=True, help="quien verifica")
    s.add_argument("--contacto", required=True, help="dueño de la clave a verificar")
    s.set_defaults(funcion=cmd_verificar)

    s = sub.add_parser("cifrar", help="RF3/RF4: cifrar y firmar un documento")
    s.add_argument("--de", required=True, help="remitente")
    s.add_argument("--para", required=True, help="destinatario")
    s.add_argument("--archivo", required=True, help="documento a enviar")
    s.add_argument("--salida", help="ruta del paquete .buzon (por defecto <archivo>.buzon)")
    s.set_defaults(funcion=cmd_cifrar)

    s = sub.add_parser("descifrar", help="RF5/RF6: verificar y descifrar un paquete")
    s.add_argument("--usuario", required=True, help="destinatario que descifra")
    s.add_argument("--paquete", required=True, help="archivo .buzon recibido")
    s.add_argument("--salida", help="carpeta donde guardar el documento")
    s.set_defaults(funcion=cmd_descifrar)

    s = sub.add_parser("auditar", help="RF7: comprobar la bitácora encadenada")
    s.set_defaults(funcion=cmd_auditar)
    return p

def main(argv=None) -> int:
    args = construir_parser().parse_args(argv)
    try:
        return args.funcion(args) or 0
    except ErrorBuzon as e:
        print(f"[X] {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperación cancelada.", file=sys.stderr)
        return 130