#!/usr/bin/env python3
# PassVerify.py: analizador de fortaleza de contraseñas (python).
# Local, sin dependencias externas (solo librería estándar; conexión a internet para --hibp).
# Uso: python3 PassVerify.py [--hibp | -h | -v]
#
# Última versión: ver VERSION más abajo.
#
# Historial de versiones (la más reciente arriba):
#
#    1.0.1 (2026-11-23) Mismo formato y salida que PassVerify.sh: -h / --help con la explicación de uso,
#                       -v / --version, una opción desconocida muestra un error y sale con código 1, colores
#                       en los mensajes y avisos uno por línea con su propio '[!]'. Si la entrada no es un
#                       terminal, la contraseña se lee de la entrada estándar (igual que en PassVerify.sh).
#    1.0.0 (2026-11-17) Primera versión. Lectura de la contraseña sin eco, estimación de entropía según longitud y
#                       alfabeto, avisos (menos de 12 caracteres, contraseñas comunes, caracteres repetidos,
#                       secuencias de teclado/alfabeto, patrón 'Palabra123!') con penalización de la entropía,
#                       nivel: de MUY DÉBIL a MUY FUERTE y consulta opcional a Have I Been Pwned (--hibp, k-anonimato).
#                       Diferentes fortalezas de contraseñas:
#                       - MUY DÉBIL
#                       - DÉBIL
#                       - ACEPTABLE
#                       - FUERTE
#                       - MUY FUERTE

import getpass
import hashlib
import math
import re
import string
import sys
import urllib.request

VERSION = "1.0.1"

# Colores (secuencias ANSI: 1 = negrita, 3X = color del texto)
endColour = "\033[0m"
blueColour = "\033[1;34m"
greenColour = "\033[1;32m"
grayColour = "\033[1;37m"
purpleColour = "\033[1;35m"
redColour = "\033[1;31m"
yellowColour = "\033[1;33m"

COMUNES = {
    "123456", "123456789", "12345678", "password", "qwerty", "abc123",
    "111111", "123123", "admin", "letmein", "welcome", "iloveyou",
    "contraseña", "contrasena", "password1", "qwerty123", "000000",
    "dragon", "football", "monkey", "master", "login", "1234", "12345",
}

SECUENCIAS = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl",
              "zxcvbnm", "0123456789"]


# Ayuda
def uso():
    print(f"{yellowColour}PassVerify{endColour}{grayColour} - Analizador de fortaleza de contraseñas{endColour}")
    print()
    print(f"{yellowColour}Uso:{endColour}")
    print(f"  {grayColour}python3 PassVerify.py [opción]{endColour}")
    print()
    print(f"{yellowColour}Opciones:{endColour}")
    print(f"  {blueColour}--hibp{endColour}        {grayColour}Además del análisis local, comprueba si la contraseña aparece{endColour}")
    print(f"                {grayColour}en filtraciones (Have I Been Pwned). Solo se envían 5 caracteres{endColour}")
    print(f"                {grayColour}del hash SHA-1, nunca la contraseña. Requiere conexión.{endColour}")
    print(f"  {blueColour}-h, --help{endColour}    {grayColour}Muestra esta ayuda y sale.{endColour}")
    print(f"  {blueColour}-v, --version{endColour} {grayColour}Muestra la versión y sale.{endColour}")
    print()
    print(f"{yellowColour}Cómo funciona:{endColour}")
    print(f"  {grayColour}El script pide la contraseña por teclado (no se muestra en pantalla),{endColour}")
    print(f"  {grayColour}estima su entropía y la clasifica de MUY DÉBIL a MUY FUERTE.{endColour}")
    print(f"  {grayColour}El análisis es local: la contraseña no se guarda ni se pasa como argumento.{endColour}")
    print()
    print(f"{yellowColour}Ejemplos:{endColour}")
    print(f"  {grayColour}python3 PassVerify.py                  {endColour}{purpleColour}# análisis local{endColour}")
    print(f"  {grayColour}python3 PassVerify.py --hibp           {endColour}{purpleColour}# + comprobación de filtraciones (Have I Been Pwned){endColour}")
    print(f"  {grayColour}python3 PassVerify.py -h | --help      {endColour}{purpleColour}# Muestra esta ayuda{endColour}")
    print(f"  {grayColour}python3 PassVerify.py -v | --version   {endColour}{purpleColour}# Muestra la versión{endColour}")


def error(mensaje: str):
    """Muestra un error en rojo por la salida de errores."""
    print(f"{redColour}[!] {mensaje}{endColour}", file=sys.stderr)


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


# Have I Been Pwned (k-anonymity)
def comprobar_hibp(pw: str):
    """Devuelve cuántas veces aparece en filtraciones (k-anonymity), o None si falla."""
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefijo, sufijo = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefijo}",
        headers={"User-Agent": "PassVerify"},
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


def leer_contrasena() -> str:
    """Lee la contraseña sin eco si hay terminal; si no, de la entrada estándar."""
    print(f"{yellowColour}[+]{endColour}{grayColour} Contraseña (no se mostrará):{endColour}", file=sys.stderr)
    if sys.stdin.isatty():
        return getpass.getpass("")
    pw = sys.stdin.readline().rstrip("\n")
    print(file=sys.stderr)
    return pw


def main():
    hibp = False
    opcion = sys.argv[1] if len(sys.argv) > 1 else ""
    if opcion == "":
        pass
    elif opcion == "--hibp":
        hibp = True
    elif opcion in ("-h", "--help"):
        uso()
        sys.exit(0)
    elif opcion in ("-v", "--version"):
        print(f"PassVerify {VERSION}")
        sys.exit(0)
    else:
        error(f"Opción desconocida: {opcion}")
        print(f"{grayColour}    Usa -h para ver cómo se utiliza.{endColour}", file=sys.stderr)
        sys.exit(1)

    pw = leer_contrasena()
    if not pw:
        error("No has introducido nada.")
        sys.exit(1)

    r = analizar(pw)
    print(f"{yellowColour}[+] {endColour}{grayColour}Longitud :{endColour}{blueColour} {r['longitud']}{endColour}")
    print(f"{yellowColour}[+] {endColour}{grayColour}Entropía :{endColour}{blueColour} ~{r['bits']:.1f} bits{endColour}")
    print(f"{yellowColour}[+] {endColour}{grayColour}Nivel    :{endColour}{blueColour} {r['nivel']}{endColour}")
    for aviso in r["avisos"]:
        print(f"{redColour}[!] {aviso}{endColour}")

    if hibp:
        veces = comprobar_hibp(pw)
        if veces is None:
            print(f"{redColour}[!] HIBP: no se pudo consultar (¿sin conexión?).{endColour}")
            return
        print("------")
        if veces:
            print(f"{redColour}[!] HIBP: Tu contraseña ¡aparece {endColour}{blueColour}{veces}{endColour}{redColour} veces en filtraciones! No la uses.{endColour}")
        else:
            print(f"{yellowColour}[+] {endColour}{greenColour}HIBP: no aparece en filtraciones conocidas.{endColour}")


if __name__ == "__main__":
    main()
