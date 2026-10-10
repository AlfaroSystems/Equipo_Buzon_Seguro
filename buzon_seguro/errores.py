"""
Excepciones del Buzón Seguro.

Los mensajes son genéricos a propósito. Ni el usuario ni un atacante que envíe
paquetes manipulados deben saber cuál control falló (formato, firma, etiqueta
GCM o hash). Si el programa respondiera distinto en cada caso, serviría como
"oráculo" para afinar un ataque (Semana 10: ataque de padding oracle).
"""

class ErrorBuzon(Exception):
    """Error controlado: se muestra al usuario sin detalles internos."""

class PaqueteRechazado(ErrorBuzon):
    """El paquete no superó alguna verificación (formato, firma, GCM o hash)."""

    def __init__(self):
        super().__init__(
            "Paquete rechazado: no se pudo comprobar su autenticidad o integridad."
        )

class ContrasenaIncorrecta(ErrorBuzon):
    """No se pudo abrir una clave privada (contraseña incorrecta o archivo dañado)."""

    def __init__(self):
        super().__init__("No se pudo abrir la clave privada. Verifique la contraseña.")

class ClaveNoConfiable(ErrorBuzon):
    """La clave pública de un contacto no está verificada o cambió en el directorio.

    Este error sí se muestra con un mensaje propio, porque el usuario necesita
    saberlo para volver a comparar la huella por un segundo canal. No revela
    nada del contenido del paquete, ya que se detecta antes de abrirlo.
    """