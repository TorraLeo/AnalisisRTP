"""
Parseo y anonimización de un chat exportado de WhatsApp.

Formatos soportados (se detectan solos):
  Android:  20/07/2026, 07:08 - +52 55 1234 5678: texto
  iPhone:   [5/12/26, 5:52:01 PM] +52 1 55 1234 5678: texto
El orden de la fecha (día/mes o mes/día) se detecta automáticamente; si es
ambiguo se puede forzar con --orden-fecha dmy|mdy.

Uso:
    python src/parse_anonymize.py ENTRADA SALIDA.parquet [--grupo NOMBRE] [--csv]

ENTRADA puede ser el .zip exportado por WhatsApp o el .txt que viene dentro.
La clave secreta (salt) para el hash de los emisores se lee de la variable de
entorno RTP_SALT o de un archivo .env en el directorio actual. Generarla una vez:
    python -c "import secrets; print(secrets.token_hex(32))"
y guardarla en .env como:  RTP_SALT=<valor>
No la suban al repositorio.

Salida: una fila por mensaje o evento del sistema, con columnas
    msg_id, grupo, fecha_hora, tipo, evento, emisor_hash,
    texto_original, texto_limpio, es_media, es_borrado, editado, reenviado,
    tiene_ubicacion, tiene_url
`texto_original` ya viene con teléfonos, menciones, correos, ubicaciones y
enlaces reemplazados; el texto crudo nunca se escribe en la salida.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import os
import re
import sys
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

# --- Formato de línea --------------------------------------------------------

_HORA = r"\d{1,2}:\d{2}(?::\d{2})?(?:[\s ]?[ap]\.?\s?m\.?)?"
# Android: "20/07/2026, 07:08 - resto"
INICIO_ANDROID = re.compile(
    rf"^(?P<fecha>\d{{1,2}}/\d{{1,2}}/\d{{2,4}}),?\s+(?P<hora>{_HORA})\s+-\s+(?P<resto>.*)$", re.I)
# iPhone: "[5/12/26, 5:52:01 PM] resto"  (los eventos del sistema traen "] - ")
INICIO_IOS = re.compile(
    rf"^‎?\[(?P<fecha>\d{{1,2}}/\d{{1,2}}/\d{{2,4}}),?\s+(?P<hora>{_HORA})\]\s+"
    rf"(?P<guion>-\s+)?(?P<resto>.*)$", re.I)

# Eventos del sistema: traen nombres y teléfonos, se guarda solo el tipo.
SISTEMA = [
    ("unio_por_enlace", re.compile(r"joined (using|via) (this |a )?(group('s)? )?(invite )?link|"
                                   r"se unió (usando|con) el enlace", re.I)),
    ("cambio_numero", re.compile(r"changed (their phone number|to \+)|cambió su número", re.I)),
    ("codigo_seguridad", re.compile(r"security code|código de seguridad", re.I)),
    ("agregado", re.compile(r"\badded\b|\bwas added\b|añadió|agregó", re.I)),
    ("salio", re.compile(r"\bleft\.?$|salió", re.I)),
    ("eliminado", re.compile(r"\bremoved\b|eliminó a", re.I)),
    ("cifrado", re.compile(r"end-to-end encrypted|cifrado de extremo", re.I)),
    ("llamada", re.compile(r"^\[Call\]|^\[Llamada\]", re.I)),
    ("notificacion", re.compile(r"^\[System notification\]|^\[Notificación", re.I)),
    ("cambio_grupo", re.compile(r"changed (the subject|this group's|the group)|created (the )?group|"
                                r"now an admin|no longer an admin|pinned a message|"
                                r"changed the settings|deleted this group's", re.I)),
]

# --- Patrones de datos personales dentro del texto ---------------------------

# Teléfonos: +52 55 1234 5678, +52 1 55 1234 5678, +1 (408) 649-1453, 5512345678...
# (?<!\d) / (?!\d) evitan confundir listas de unidades ("5174 5238 5230").
TELEFONO = re.compile(
    r"(?<![\d\w])(?:\+\d{1,3}[\s\-]?(?:1[\s\-]?)?)?"
    r"\(?\d{2,3}\)?[\s\-]?\d{3,4}[\s\-]?\d{4}(?!\d)"
)
# Teléfono escrito en pares: "55 11 49 31 27"
TELEFONO_PARES = re.compile(r"(?<!\d)\d{2}(?:[\s\-]\d{2}){4}(?!\d)")
# Tarjetas: 16 dígitos que además pasan Luhn (para no tachar listas de unidades).
TARJETA = re.compile(r"(?<!\d)\d{4}(?:[\s\-]?\d{4}){3}(?!\d)")
MENCION = re.compile(r"@⁨[^⁩]*⁩|@\+?\d{8,}")
CORREO = re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+")
# "Live location: 19.36, -99.24 - https://maps..."  /  "location: https://maps..."
UBICACION = re.compile(
    r"(?:(?:live )?location|ubicación(?: en tiempo real)?)\s*:\s*"
    r"(?:-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+)?(?:\s*-\s*)?(?:https?://\S+)?"
    r"|https?://maps\.google\.\S+"
    r"|-?\d{1,2}\.\d{4,}\s*,\s*-?\d{2,3}\.\d{4,}",
    re.I,
)
URL = re.compile(r"https?://\S+")
# Tarjetas de contacto completas dentro del texto (nombre + teléfono en waid=).
VCARD = re.compile(r"(?:Contact:\s*)?BEGIN:VCARD.*?END:VCARD", re.S | re.I)
# Imágenes incrustadas en base64 (pueden traer metadatos, incluido GPS).
BASE64 = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

MEDIA = re.compile(
    r"<Media omitted>|<Multimedia omitido>|<attached:[^>]*>|"
    r"<?\b(?:image|video|audio|sticker|GIF|document|voice message|Contact card|"
    r"imagen|sticker|audio|documento|GIF) (?:omitted|omitid[oa])>?|"
    r"\(file attached\)|archivo adjunto",
    re.I,
)
BORRADO = re.compile(r"^(This message was deleted|You deleted this message|"
                     r"Se eliminó este mensaje|Eliminaste este mensaje)\.?$", re.I)
EDITADO = re.compile(r"\s*<(This message was edited|Se editó este mensaje\.?)>", re.I)
REENVIADO = re.compile(r"^\s*\[(Forwarded|Reenviado)\]\s*", re.I)
INVISIBLES = re.compile(r"[‎‏‪-‮⁦-⁩﻿]")


# --- Utilidades --------------------------------------------------------------

def luhn_valido(numero: str) -> bool:
    digitos = [int(d) for d in re.sub(r"\D", "", numero)][::-1]
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2)
                for i, d in enumerate(digitos))
    return total % 10 == 0


def cargar_salt() -> bytes:
    salt = os.environ.get("RTP_SALT")
    env = Path(".env")
    if not salt and env.exists():
        for linea in env.read_text(encoding="utf-8").splitlines():
            if linea.strip().startswith("RTP_SALT="):
                salt = linea.split("=", 1)[1].strip().strip('"').strip("'")
    if not salt or len(salt) < 16:
        sys.exit("Falta RTP_SALT (mín. 16 caracteres). Ver instrucciones al inicio del script.")
    return salt.encode()


def leer_texto(ruta: Path) -> str:
    if ruta.suffix.lower() == ".zip":
        with zipfile.ZipFile(ruta) as z:
            txts = [n for n in z.namelist() if n.lower().endswith(".txt")]
            if len(txts) != 1:
                sys.exit(f"El zip debe contener exactamente un .txt (encontrados: {txts})")
            # Los .vcf y demás adjuntos del zip se ignoran a propósito.
            return io.TextIOWrapper(z.open(txts[0]), encoding="utf-8-sig").read()
    return ruta.read_text(encoding="utf-8-sig")


def normalizar_emisor(emisor: str) -> str:
    emisor = INVISIBLES.sub("", emisor).replace(" ", " ").strip().lstrip("~").strip()
    digitos = re.sub(r"\D", "", emisor)
    if emisor.startswith("+") and len(digitos) >= 8:
        # "+52 1 55 ..." (formato móvil antiguo de México) = "+52 55 ..."
        if digitos.startswith("521") and len(digitos) == 13:
            digitos = "52" + digitos[3:]
        return digitos
    return emisor.casefold()


def hash_emisor(emisor: str, salt: bytes) -> str:
    return hmac.new(salt, normalizar_emisor(emisor).encode(), hashlib.sha256).hexdigest()[:16]


def anonimizar_texto(texto: str, contador: Counter) -> str:
    # Un mensaje con datos bancarios se redacta completo: suele traer
    # también nombre del titular y banco, y no aporta al análisis.
    if any(luhn_valido(m.group()) for m in TARJETA.finditer(texto)):
        contador["tarjeta"] += 1
        return "<REDACTADO>"
    for nombre, patron, marca in (
        ("contacto", VCARD, "<CONTACTO>"),
        ("imagen_base64", BASE64, "<IMAGEN>"),
        ("ubicacion", UBICACION, "<UBICACION>"),
        ("correo", CORREO, "<EMAIL>"),
        ("mencion", MENCION, "<USR>"),
        ("url", URL, "<URL>"),
        ("telefono", TELEFONO, "<TEL>"),
        ("telefono", TELEFONO_PARES, "<TEL>"),
    ):
        texto, n = patron.subn(marca, texto)
        contador[nombre] += n
    return texto


def limpiar(texto: str) -> str:
    texto = INVISIBLES.sub("", texto).replace(" ", " ").replace(" ", " ")
    texto = EDITADO.sub("", texto)
    texto = REENVIADO.sub("", texto)
    lineas = [re.sub(r"[ \t]+", " ", l).strip() for l in texto.split("\n")]
    return "\n".join(l for l in lineas if l)


def evento_sistema(texto: str) -> str | None:
    for nombre, patron in SISTEMA:
        if patron.search(texto):
            return nombre
    return None


def detectar_orden_fecha(fechas: list[str]) -> str:
    primero = any(int(f.split("/")[0]) > 12 for f in fechas)
    segundo = any(int(f.split("/")[1]) > 12 for f in fechas)
    if primero and not segundo:
        return "dmy"
    if segundo and not primero:
        return "mdy"
    print("AVISO: no se pudo detectar el orden de la fecha; se asume día/mes/año. "
          "Usa --orden-fecha si no es correcto.")
    return "dmy"


def parsear_fecha(fecha: str, hora: str, orden: str) -> datetime:
    d, m, a = fecha.split("/") if orden == "dmy" else (fecha.split("/")[1], fecha.split("/")[0],
                                                        fecha.split("/")[2])
    a = int(a) + (2000 if len(a) == 2 else 0)
    hora = re.sub(r"[\s ]+", " ", hora).replace(".", "").upper().replace(" M", "M")
    for fmt in ("%H:%M", "%H:%M:%S", "%I:%M %p", "%I:%M:%S %p", "%I:%M%p", "%I:%M:%S%p"):
        try:
            t = datetime.strptime(hora, fmt)
            return datetime(a, int(m), int(d), t.hour, t.minute, t.second)
        except ValueError:
            continue
    raise ValueError(f"Hora no reconocida: {hora!r}")


# --- Proceso principal -------------------------------------------------------

def separar_lineas(texto_chat: str) -> list[dict]:
    lineas = texto_chat.splitlines()
    muestra = [l for l in lineas[:500] if l.strip()]
    ios = sum(bool(INICIO_IOS.match(l)) for l in muestra) > sum(bool(INICIO_ANDROID.match(l)) for l in muestra)
    patron = INICIO_IOS if ios else INICIO_ANDROID

    crudos: list[dict] = []
    for linea in lineas:
        m = patron.match(linea)
        if m:
            crudos.append({
                "fecha": m["fecha"], "hora": m["hora"], "resto": m["resto"],
                # En iPhone el "] - " marca un evento del sistema.
                "sistema_ios": bool(ios and m.groupdict().get("guion")),
            })
        elif crudos:
            crudos[-1]["resto"] += "\n" + linea  # continuación de un mensaje de varias líneas
        # Líneas antes del primer encabezado (aviso de cifrado, etc.) se descartan.
    print(f"Formato detectado: {'iPhone' if ios else 'Android'}")
    return crudos


def procesar(texto_chat: str, grupo: str, salt: bytes, orden: str | None = None
             ) -> tuple[pd.DataFrame, Counter]:
    crudos = separar_lineas(texto_chat)
    if not crudos:
        sys.exit("No se reconoció ningún mensaje. ¿Es una exportación de WhatsApp?")
    orden = orden or detectar_orden_fecha([c["fecha"] for c in crudos])
    print(f"Orden de fecha: {orden}")

    contador: Counter = Counter()
    filas = []
    for i, c in enumerate(crudos):
        fila = {"msg_id": i, "grupo": grupo,
                "fecha_hora": parsear_fecha(c["fecha"], c["hora"], orden)}
        resto = c["resto"]
        primera = resto.split("\n", 1)[0]
        if c["sistema_ios"]:
            evento = evento_sistema(primera) or "otro_sistema"
        elif ": " in primera:
            # Se revisa solo lo que estaría antes de ": " (el supuesto emisor), para
            # atrapar eventos como 'X changed the subject from "a: b"'.
            evento = evento_sistema(primera.split(": ", 1)[0])
        else:
            evento = evento_sistema(primera) or "otro_sistema"

        if evento:
            contador["eventos_sistema"] += 1
            fila.update(tipo="sistema", evento=evento, emisor_hash=None,
                        texto_original=None, texto_limpio=None, es_media=False,
                        es_borrado=False, editado=False, reenviado=False,
                        tiene_ubicacion=False, tiene_url=False)
            filas.append(fila)
            continue

        emisor, cuerpo = resto.split(": ", 1)
        base = limpiar(cuerpo)
        editado = bool(EDITADO.search(cuerpo))
        reenviado = bool(REENVIADO.match(INVISIBLES.sub("", cuerpo)))
        es_borrado = bool(BORRADO.match(base))
        anonimo = INVISIBLES.sub("", anonimizar_texto(cuerpo, contador))
        es_media = bool(MEDIA.search(cuerpo)) or "<CONTACTO>" in anonimo or "<IMAGEN>" in anonimo
        if es_borrado:
            limpio = ""
        else:
            limpio = limpiar(re.sub(r"<CONTACTO>|<IMAGEN>", "", MEDIA.sub("", anonimo)))
        fila.update(
            tipo="mensaje", evento=None, emisor_hash=hash_emisor(emisor, salt),
            texto_original=anonimo, texto_limpio=limpio, es_media=es_media,
            es_borrado=es_borrado, editado=editado, reenviado=reenviado,
            tiene_ubicacion="<UBICACION>" in anonimo, tiene_url="<URL>" in anonimo,
        )
        filas.append(fila)

    df = pd.DataFrame(filas)
    df["fecha_hora"] = pd.to_datetime(df["fecha_hora"])
    return df, contador


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("entrada", type=Path)
    ap.add_argument("salida", type=Path)
    ap.add_argument("--grupo", default="rtp120", help="identificador del grupo (default: rtp120)")
    ap.add_argument("--orden-fecha", choices=["dmy", "mdy"], help="forzar orden de la fecha")
    ap.add_argument("--csv", action="store_true", help="también escribe una copia .csv")
    args = ap.parse_args()

    salt = cargar_salt()
    df, contador = procesar(leer_texto(args.entrada), args.grupo, salt, args.orden_fecha)

    args.salida.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.salida, index=False)
    if args.csv:
        df.to_csv(args.salida.with_suffix(".csv"), index=False, encoding="utf-8-sig")

    msgs = df[df.tipo == "mensaje"]
    print(f"Filas: {len(df):,}  (mensajes {len(msgs):,}, eventos del sistema {contador['eventos_sistema']:,})")
    print(f"Rango: {df.fecha_hora.min()} → {df.fecha_hora.max()}")
    print(f"Emisores distintos: {msgs.emisor_hash.nunique():,}")
    print(f"Media {msgs.es_media.sum():,} · borrados {msgs.es_borrado.sum():,} · "
          f"editados {msgs.editado.sum():,} · reenviados {msgs.reenviado.sum():,}")
    print("Reemplazos:", {k: v for k, v in contador.items() if k != "eventos_sistema"})
    resto = msgs.texto_original.str.contains(r"\d{10,}|\+\d{2}\s?\d|\d+\.\d{4,}", regex=True, na=False).sum()
    if resto:
        print(f"AVISO: {resto} mensajes aún contienen secuencias largas de dígitos; revisarlos.")
    print(f"Escrito: {args.salida}")


if __name__ == "__main__":
    main()
