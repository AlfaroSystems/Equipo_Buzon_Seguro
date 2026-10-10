# Buzón Seguro

Herramienta de línea de comandos para enviar documentos de forma **confidencial, íntegra y autenticada**, aunque el canal sea público.

Tarea en equipo de Gestión de Sistemas de Seguridad de la Información (GSSI), Universidad de Oriente (UNIVO). Caso: Cooperativa Oriente Solidario.

| Propiedad | Cómo se logra |
|---|---|
| Confidencialidad | ECDH efímero X25519 + HKDF-SHA256 + AES-256-GCM |
| Integridad | Etiqueta GCM, firma Ed25519 y SHA-256 del documento original |
| Autenticidad y no repudio | Firma Ed25519 del remitente, con clave verificada por huella |
| Trazabilidad | Bitácora con hashes SHA-256 encadenados |

---

## 1. Requisitos

- Python 3.10 o superior (probado con Python 3.12 en Windows 11)
- Biblioteca [`cryptography`](https://cryptography.io); `pytest` solo para las pruebas automatizadas

Funciona igual en Windows, macOS y Linux.

## 2. Instalación

```bash
git clone https://github.com/AlfaroSystems/Equipo_Buzon_Seguro.git
cd Equipo_Buzon_Seguro
python -m venv .venv
```

Activar el entorno virtual:

- **Windows (PowerShell):** `.venv\Scripts\Activate.ps1`
- **macOS / Linux:** `source .venv/bin/activate`

Si PowerShell no permite ejecutar el script de activación, se puede omitir y usar directamente `.venv\Scripts\python.exe` en lugar de `python` en todos los comandos.

Instalar las dependencias:

```bash
pip install -r requirements.txt
```

## 3. Uso rápido: Ana envía una solicitud a Beto

Todos los comandos se ejecutan desde la carpeta del proyecto. Las contraseñas se piden sin mostrarlas en pantalla y deben tener al menos 12 caracteres.

```bash
# 1. Cada persona crea su identidad (claves X25519 y Ed25519)
python buzon.py generar --usuario ana.lopez
python buzon.py generar --usuario beto.martinez

# 2. Cada uno verifica la huella del otro POR UN SEGUNDO CANAL (en persona o por teléfono)
python buzon.py verificar --usuario ana.lopez --contacto beto.martinez
python buzon.py verificar --usuario beto.martinez --contacto ana.lopez

# 3. Ana cifra y firma el documento para Beto
python buzon.py cifrar --de ana.lopez --para beto.martinez --archivo solicitud_credito_0045.pdf

# 4. Beto verifica la firma y descifra
python buzon.py descifrar --usuario beto.martinez --paquete solicitud_credito_0045.pdf.buzon

# 5. Revisar que nadie haya alterado la bitácora
python buzon.py auditar
```

El documento descifrado se guarda en `datos/usuarios/beto.martinez/recibidos/`.

### Comandos

| Comando | Requerimiento | Qué hace |
|---|---|---|
| `generar --usuario U` | RF1 | Crea los pares X25519 y Ed25519. Las privadas se guardan cifradas con contraseña (PKCS#8) y las públicas van al directorio. |
| `huella --usuario U` | RF2 | Muestra la huella SHA-256 de las claves públicas de U. |
| `verificar --usuario U --contacto C` | RF2 | Tras comparar la huella por otro canal, U marca la clave de C como verificada. |
| `cifrar --de U --para C --archivo F` | RF3, RF4, RF6 | Cifra F para C (solo si C está verificado) y lo firma. Genera `F.buzon`. |
| `descifrar --usuario U --paquete P` | RF5, RF6 | Verifica la firma **antes** de descifrar, descifra y comprueba el SHA-256. |
| `auditar` | RF7 | Recorre la bitácora encadenada e indica la primera línea alterada. |

Ayuda de cualquier comando: `python buzon.py <comando> -h`.

## 4. Pruebas de seguridad (P1 a P8)

### Automatizadas

```bash
python -m pytest -v
```

`tests/test_seguridad.py` contiene los ocho escenarios del apartado 5 y pruebas adicionales de los RF. Cada prueba indica en su descripción el control criptográfico que produce el resultado. Las contraseñas de prueba se generan al azar, así que no hay ninguna escrita en el código.

### Demostración en vivo

`atacante.py` simula los ataques **solo contra nuestro propio sistema**. Primero hay que completar los pasos 1 a 3 del uso rápido.

| Prueba | Comandos | Resultado esperado |
|---|---|---|
| **P1** Envío normal | `python buzon.py descifrar --usuario beto.martinez --paquete solicitud_credito_0045.pdf.buzon` | Documento idéntico, SHA-256 coincide, firma válida |
| **P2** Un byte alterado | `python atacante.py alterar-byte --paquete solicitud_credito_0045.pdf.buzon`<br>`python buzon.py descifrar --usuario beto.martinez --paquete solicitud_credito_0045.pdf_alterado.buzon` | Rechazo (falla la firma y la etiqueta GCM) |
| **P3** Metadatos alterados | `python atacante.py cambiar-metadato --paquete solicitud_credito_0045.pdf.buzon --campo destinatario --valor carlos.ruiz`<br>`python buzon.py descifrar --usuario beto.martinez --paquete solicitud_credito_0045.pdf_metadatos.buzon` | Rechazo (AAD autenticado y firmado) |
| **P4** Otro usuario | `python buzon.py generar --usuario carlos.ruiz`<br>`python buzon.py verificar --usuario carlos.ruiz --contacto ana.lopez`<br>`python buzon.py descifrar --usuario carlos.ruiz --paquete solicitud_credito_0045.pdf.buzon` | Rechazo: Carlos no puede derivar la clave |
| **P5** Suplantación | `python buzon.py generar --usuario mallory`<br>`python atacante.py suplantar --mallory mallory --victima ana.lopez --para beto.martinez --archivo orden.txt`<br>`python buzon.py descifrar --usuario beto.martinez --paquete orden.txt.buzon`<br>`python atacante.py restaurar --victima ana.lopez` | Alerta: la huella no coincide con la verificada |
| **P6** Contraseña incorrecta | `python buzon.py descifrar ...` y escribir una contraseña equivocada | Error controlado, sin detalles |
| **P7** Bitácora editada | `python atacante.py alterar-bitacora --linea 3`<br>`python buzon.py auditar` | Indica la línea 3 como alterada |
| **P8** Mismo documento dos veces | `python buzon.py cifrar --de ana.lopez --para beto.martinez --archivo solicitud_credito_0045.pdf --salida segundo.buzon`<br>`python atacante.py comparar solicitud_credito_0045.pdf.buzon segundo.buzon` | Clave efímera, nonce, cifrado y firma distintos |

Para P5, `orden.txt` puede ser cualquier archivo de texto, por ejemplo uno que diga "Desembolsar $10,000 a la cuenta 99-999".

## 5. Diseño criptográfico

**Envío** (`cifrar`):

1. Se comprueba que la huella del destinatario sigue siendo la que se verificó (RF2).
2. Se genera un par X25519 **efímero**, nuevo para cada documento.
3. `secreto = ECDH(efímera_privada, x25519_pública_destinatario)`
4. `clave = HKDF-SHA256(secreto, info = b"buzon-seguro-v1")`, 32 bytes.
5. `contenido = {"sha256_original": ..., "datos": ...}` (RF6)
6. `cifrado = AES-256-GCM(clave, nonce aleatorio de 12 bytes, contenido, AAD = metadatos)`
7. `firma = Ed25519(efímera_pub || nonce || metadatos || cifrado)` con la clave privada del remitente (RF4).
8. La clave efímera privada no se guarda en ninguna parte.

**Recepción** (`descifrar`): formato válido → huella del remitente verificada → **firma** → contraseña → ECDH + HKDF → **AES-GCM** → **SHA-256**. Si algo falla, el mensaje es genérico y no indica qué control falló.

Formato del paquete `.buzon`: Anexo B de la tarea. Los metadatos se serializan siempre igual (`json.dumps(..., sort_keys=True)`) para firmar, verificar y usarlos como AAD.

## 6. Estructura del proyecto

```
buzon.py                 Punto de entrada de la línea de comandos
atacante.py              Demostración de ataques P2, P3, P5, P7 y P8
buzon_seguro/
├── identidad.py         RF1 y RF2: claves, huellas y verificación
├── paquete.py           RF3 a RF6: cifrar, firmar, verificar y descifrar
├── bitacora.py          RF7: bitácora encadenada y auditoría
├── almacen.py           Rutas, archivos JSON y validación de nombres
├── errores.py           Errores con mensajes genéricos
└── cli.py               Comandos y mensajes al usuario
tests/test_seguridad.py  Pruebas automatizadas P1 a P8
```

Datos que genera el programa (en `datos/`, **excluidos del repositorio** por `.gitignore`):

```
datos/directorio/<usuario>.json        claves públicas (carpeta compartida, NO confiable)
datos/usuarios/<usuario>/*.pem         claves privadas cifradas con contraseña
datos/usuarios/<usuario>/confianza.json  huellas verificadas por ese usuario
datos/usuarios/<usuario>/recibidos/    documentos descifrados
datos/bitacora.jsonl                   bitácora encadenada
```

Para usar otra carpeta de datos se define la variable de entorno `BUZON_DATOS`.

## 7. Decisiones de seguridad

- **Biblioteca profesional.** Solo se usa `cryptography`; no hay algoritmos propios.
- **Aleatoriedad.** Claves con `generate()` y nonces con `os.urandom`, ambos del generador seguro del sistema.
- **Claves privadas.** Se guardan en PKCS#8 cifradas con `BestAvailableEncryption`, y las contraseñas se piden con `getpass`.
- **Verificar antes de descifrar.** La contraseña del destinatario se pide recién cuando la firma ya resultó válida.
- **Errores genéricos.** Ante formato, firma, GCM o hash inválidos se muestra el mismo mensaje, así el programa no sirve como "oráculo".
- **Nombres validados.** Los usuarios y archivos que vienen en un paquete se validan para impedir escribir fuera de las carpetas (por ejemplo, con `../../`).
- **Nada sensible en el repositorio.** `datos/`, `*.pem` y `*.buzon` están en `.gitignore`.

## 8. Limitaciones conocidas

- `BestAvailableEncryption` deriva la clave con **PBKDF2-SHA256 de solo 2,048 iteraciones** (comprobado con `openssl asn1parse`). Para compensar se exigen contraseñas de 12 caracteres o más. Ver el caso LastPass, Semana 8.
- **Secreto hacia adelante parcial.** Si se roba la clave fija del remitente, sus envíos anteriores no se pueden descifrar porque se usó una clave efímera. Pero si se roba la clave privada X25519 de un destinatario (y su contraseña), sí se pueden descifrar los paquetes que ya recibió.
- **Reescritura completa de la bitácora.** Quien la reescriba completa desde la línea alterada hasta el final no se detecta solo con la cadena. Por eso `auditar` muestra el hash final, que conviene anotar fuera del sistema.
- **Equipo infectado.** No protege contra un equipo comprometido (keylogger o malware) ni contra un destinatario legítimo que reenvíe el documento ya descifrado.
- **Computación cuántica.** X25519 y Ed25519 caerían ante un computador cuántico (algoritmo de Shor). La migración prevista es a ML-KEM y ML-DSA. AES-256 y SHA-256 siguen siendo seguros.
- `confianza.json` se protege solo con los permisos de la carpeta del usuario.

## 9. Equipo

| Integrante | Rol |
|---|---|
| _(completar)_ | Coordinación, código y pruebas |
| _(completar)_ | Modelo de amenazas y diseño |
| _(completar)_ | Justificación de algoritmos y política de claves |
| _(completar)_ | Limitaciones, plan poscuántico y referencias |
