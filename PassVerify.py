#!/usr/bin/env python3
"""passcheck: analizador sencillo de fortaleza de contraseñas.

- Funciona 100% en local (la contraseña no sale de tu equipo).
- Sin dependencias externas (solo librería estándar).
- Opcional: --hibp comprueba si la contraseña aparece en filtraciones usando
  la API de Have I Been Pwned con k-anonymity (solo se envían 5 caracteres del hash).

Uso:
    python passcheck.py              # pide la contraseña sin mostrarla
    python passcheck.py --hibp       # además consulta filtraciones
"""
import argparse
import getpass
import hashlib
import math
import re
import string
import sys
import urllib.request

COMUNES = {
    "123456", "123456789", "12345678", "password", "qwerty", "abc123",
    "111111", "123123", "admin", "letmein", "welcome", "iloveyou",
    "contraseña", "contrasena", "password1", "qwerty123", "000000",
    "dragon", "football", "monkey", "master", "login", "1234", "12345",
}

SECUENCIAS = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl",
              "zxcvbnm", "0123456789"]


def entropia_bits(pw: str) -> float:
    """Estimación: longitud * log2(tamaño del alfabeto usado)."""
    alfabeto = 0
    if re.search(r"[a-z]", pw):
        alfabeto += 26
    if re.search(r"[A-Z]", pw):
        alfabeto += 26
    if re.search(r"\d", pw):
        alfabeto += 10
    if re.search(r"[%s]" % re.escape(string.punctuation), pw):
        alfabeto += len(string.punctuation)
    if re.search(r"[^\x00-\x7F]", pw):
        alfabeto += 30
    return len(pw) * math.log2(alfabeto) if alfabeto else 0.0


def tiene_secuencia(pw: str, n: int = 4) -> bool:
    bajo = pw.lower()
    for seq in SECUENCIAS:
        for i in range(len(seq) - n + 1):
            trozo = seq[i:i + n]
            if trozo in bajo or trozo[::-1] in bajo:
                return True
    return False


def analizar(pw: str) -> dict:
    avisos = []
    bits = entropia_bits(pw)

    if len(pw) < 12:
        avisos.append("Menos de 12 caracteres: alárgala.")
    if pw.lower() in COMUNES:
        avisos.append("Es una de las contraseñas más usadas.")
        bits = min(bits, 10)
    if re.search(r"(.)\1{2,}", pw):
        avisos.append("Tiene caracteres repetidos (aaa, 111...).")
        bits *= 0.8
    if tiene_secuencia(pw):
        avisos.append("Contiene secuencias previsibles (abcd, 1234, qwer...).")
        bits *= 0.8
    if re.fullmatch(r"[A-Za-z]+\d{1,4}[!@#$%^&*.]?", pw):
        avisos.append("Patrón típico 'Palabra123!': fácil de adivinar.")
        bits *= 0.7

    if bits < 40:
        nivel = "MUY DÉBIL"
    elif bits < 60:
        nivel = "DÉBIL"
    elif bits < 80:
        nivel = "ACEPTABLE"
    elif bits < 100:
        nivel = "FUERTE"
    else:
        nivel = "MUY FUERTE"

    return {"longitud": len(pw), "bits": round(bits, 1), "nivel": nivel, "avisos": avisos}


def comprobar_hibp(pw: str):
    """Devuelve cuántas veces aparece en filtraciones (k-anonymity), o None si falla."""
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefijo, sufijo = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefijo}",
        headers={"User-Agent": "passcheck-educational"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            for linea in r.read().decode().splitlines():
                h, _, veces = linea.partition(":")
                if h == sufijo:
                    return int(veces)
        return 0
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description="Analiza la fortaleza de una contraseña.")
    ap.add_argument("--hibp", action="store_true",
                    help="Consultar Have I Been Pwned (k-anonymity)")
    args = ap.parse_args()

    pw = getpass.getpass("Contraseña (no se mostrará): ")
    if not pw:
        sys.exit("No has introducido nada.")

    r = analizar(pw)
    print(f"\nLongitud : {r['longitud']}")
    print(f"Entropía : ~{r['bits']} bits")
    print(f"Nivel    : {r['nivel']}")
    for a in r["avisos"]:
        print(f"  ! {a}")

    if args.hibp:
        veces = comprobar_hibp(pw)
        if veces is None:
            print("\nHIBP: no se pudo consultar (¿sin conexión?).")
        elif veces:
            print(f"\nHIBP: ¡aparece {veces} veces en filtraciones! No la uses.")
        else:
            print("\nHIBP: no aparece en filtraciones conocidas.")


if __name__ == "__main__":
    main()
