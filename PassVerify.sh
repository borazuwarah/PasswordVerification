#!/bin/sh
# PasswordVerification.sh: analizador de fortaleza de contraseñas (POSIX sh).
# Local, sin dependencias salvo utilidades estándar (awk, grep, tr; curl y sha1sum/shasum para --hibp).
# Uso: ./PassVerify.sh [--hibp]


#Colours
endColour="\033[0m\e[0m"
blueColour="\e[0;34m\033[1m"
greenColour="\e[0;32m\033[1m"
grayColour="\e[0;37m\033[1m"
purpleColour="\e[0;35m\033[1m"
redColour="\e[0;31m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
yellowColour="\e[0;33m\033[1m"


HIBP=0
[ "${1:-}" = "--hibp" ] && HIBP=1

# Leer la contraseña sin eco
printf 'Contraseña (no se mostrará): ' >&2
if [ -t 0 ]; then
    stty -echo
    trap 'stty echo' EXIT INT TERM
fi
IFS= read -r PW
if [ -t 0 ]; then stty echo; trap - EXIT INT TERM; fi
printf '\n' >&2

[ -n "$PW" ] || { echo "No has introducido nada." >&2; exit 1; }

LEN=${#PW}
LOW=$(printf '%s' "$PW" | tr '[:upper:]' '[:lower:]')
AVISOS=""
FACTOR=100          # porcentaje aplicado a la entropía
TOPE=""             # tope de entropía (contraseñas comunes)

# Alfabeto estimado
ALFA=0
case $PW in *[[:lower:]]*) ALFA=$((ALFA + 26));; esac
case $PW in *[[:upper:]]*) ALFA=$((ALFA + 26));; esac
case $PW in *[[:digit:]]*) ALFA=$((ALFA + 10));; esac
case $PW in *[[:punct:]]*) ALFA=$((ALFA + 32));; esac

# Comprobaciones
[ "$LEN" -lt 12 ] && AVISOS="$AVISOS  ! Menos de 12 caracteres: alárgala.
"

case $LOW in
    123456|123456789|12345678|password|qwerty|abc123|111111|123123|admin|\
    letmein|welcome|iloveyou|contraseña|contrasena|password1|qwerty123|\
    000000|dragon|football|monkey|master|login|1234|12345)
        AVISOS="$AVISOS  ! Es una de las contraseñas más usadas.
"
        TOPE=10;;
esac

if printf '%s\n' "$PW" | grep -Eq '(.)\1\1'; then
    AVISOS="$AVISOS  ! Tiene caracteres repetidos (aaa, 111...).
"
    FACTOR=$((FACTOR * 80 / 100))
fi

if PW_LOW="$LOW" awk 'BEGIN {
    pw = ENVIRON["PW_LOW"]
    n = split("abcdefghijklmnopqrstuvwxyz qwertyuiop asdfghjkl zxcvbnm 0123456789", s, " ")
    for (k = 1; k <= n; k++)
        for (i = 1; i <= length(s[k]) - 3; i++) {
            t = substr(s[k], i, 4); r = ""
            for (j = 4; j >= 1; j--) r = r substr(t, j, 1)
            if (index(pw, t) || index(pw, r)) exit 0
        }
    exit 1 }'; then
    AVISOS="$AVISOS  ! Contiene secuencias previsibles (abcd, 1234, qwer...).
"
    FACTOR=$((FACTOR * 80 / 100))
fi

if printf '%s\n' "$PW" | grep -Eq '^[[:alpha:]]+[0-9]{1,4}[!@#$%^&*.]?$'; then
    AVISOS="$AVISOS  ! Patrón típico 'Palabra123!': fácil de adivinar.
"
    FACTOR=$((FACTOR * 70 / 100))
fi

# Entropía
BITS=$(awk -v l="$LEN" -v a="$ALFA" -v f="$FACTOR" -v t="${TOPE:-0}" 'BEGIN {
    b = (a > 0) ? l * log(a) / log(2) : 0
    if (t > 0 && b > t) b = t
    printf "%.1f", b * f / 100 }')

NIVEL=$(awk -v b="$BITS" 'BEGIN {
    if (b < 40) print "MUY DÉBIL"; else if (b < 60) print "DÉBIL";
    else if (b < 80) print "ACEPTABLE"; else if (b < 100) print "FUERTE";
    else print "MUY FUERTE" }')

printf '\nLongitud : %s\nEntropía : ~%s bits\nNivel    : %s\n' "$LEN" "$BITS" "$NIVEL"
printf '%s' "$AVISOS"

# Have I Been Pwned (k-anonymity)
if [ "$HIBP" -eq 1 ]; then
    if command -v sha1sum >/dev/null 2>&1; then SHA=sha1sum; else SHA="shasum -a 1"; fi
    HASH=$(printf '%s' "$PW" | $SHA | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
    PRE=$(printf '%s' "$HASH" | cut -c1-5)
    SUF=$(printf '%s' "$HASH" | cut -c6-)
    if RESP=$(curl -fsS -m 8 "https://api.pwnedpasswords.com/range/$PRE" 2>/dev/null); then
        VECES=$(printf '%s\n' "$RESP" | tr -d '\r' | grep "^$SUF:" | cut -d: -f2)
        if [ -n "$VECES" ]; then
            printf '\nHIBP: ¡aparece %s veces en filtraciones! No la uses.\n' "$VECES"
        else
            printf '\nHIBP: no aparece en filtraciones conocidas.\n'
        fi
    else
        printf '\nHIBP: no se pudo consultar (¿sin conexión?).\n'
    fi
fi
