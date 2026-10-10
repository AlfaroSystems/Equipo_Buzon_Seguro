"""
Buzón Seguro · Tarea en equipo GSSI (UNIVO).

Punto de entrada. Ejemplos:
    python buzon.py -h
    python buzon.py generar --usuario ana.lopez
    python buzon.py cifrar --de ana.lopez --para beto.martinez --archivo solicitud.pdf
"""
import sys

from buzon_seguro.cli import main

if __name__ == "__main__":
    sys.exit(main())
