#!/bin/sh
# PassVerify.sh: analizador de fortaleza de contraseñas (POSIX sh).
# Local, sin dependencias salvo utilidades estándar (awk, grep, tr; curl y sha1sum/shasum para --hibp).
# Uso: ./PassVerify.sh [--hibp]
#
# Historial de versiones (la más reciente arriba):
#
#    1.0.1 (2026-11-19) Corregido el nivel de fortaleza con locales que usan coma decimal (p. ej. es_ES): awk
#                       escribía la entropía como "104,9", el segundo awk la comparaba como texto y daba niveles
#                       absurdos (≥100 bits salía MUY DÉBIL, 80–99,9 salía MUY FUERTE). Ahora entropía y nivel se
#                       calculan en un único awk con LC_ALL=C, así que el decimal siempre es '.'. Los mensajes de
#                       salida pasan de printf a echo; la contraseña se sigue pasando con printf a tr/grep/sha1sum
#                       (el echo de dash interpreta '\' y añade un salto de línea, lo que alteraría el análisis y
#                       el hash de HIBP).
#    1.0.0 (2026-11-18) Primera versión. Lectura de la contraseña sin eco, estimación de entropía según longitud y
#                       alfabeto, avisos (menos de 12 caracteres, contraseñas comunes, caracteres repetidos,
#                       secuencias de teclado/alfabeto, patrón 'Palabra123!') con penalización de la entropía,
#                       nivel de MUY DÉBIL a MUY FUERTE y consulta opcional a Have I Been Pwned (--hibp, k-anonimato).


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
echo  "${yellowColour}[+]${endColour} Contraseña (no se mostrará):"  >&2
if [ -t 0 ]; then
    stty -echo
    trap 'stty echo' EXIT INT TERM
fi
IFS= read -r PW
if [ -t 0 ]; then stty echo; trap - EXIT INT TERM; fi
echo >&2

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

# Entropía y nivel (LC_ALL=C para que el decimal sea siempre '.')
set -- $(LC_ALL=C awk -v l="$LEN" -v a="$ALFA" -v f="$FACTOR" -v t="${TOPE:-0}" 'BEGIN {
    b = (a > 0) ? l * log(a) / log(2) : 0
    if (t > 0 && b > t) b = t
    b = b * f / 100
    n = (b < 40) ? 1 : (b < 60) ? 2 : (b < 80) ? 3 : (b < 100) ? 4 : 5
    printf "%.1f %d", b, n }')
BITS=$1
case $2 in
    1) NIVEL="MUY DÉBIL";; 2) NIVEL="DÉBIL";; 3) NIVEL="ACEPTABLE";;
    4) NIVEL="FUERTE";; *) NIVEL="MUY FUERTE";;
esac

echo
echo "${yellowColour}[+] ${endColour}${grayColour}Longitud : $LEN${endColour}"
echo "Entropía : ~$BITS bits"
echo "Nivel    : $NIVEL"
# ${AVISOS%?} quita el salto de línea final para no dejar una línea en blanco
if [ -n "$AVISOS" ]; then echo "${AVISOS%?}"; fi

# Have I Been Pwned (k-anonymity)
if [ "$HIBP" -eq 1 ]; then
    if command -v sha1sum >/dev/null 2>&1; then SHA=sha1sum; else SHA="shasum -a 1"; fi
    HASH=$(printf '%s' "$PW" | $SHA | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
    PRE=$(echo "$HASH" | cut -c1-5)
    SUF=$(echo "$HASH" | cut -c6-)
    if RESP=$(curl -fsS -m 8 "https://api.pwnedpasswords.com/range/$PRE" 2>/dev/null); then
        VECES=$(echo "$RESP" | tr -d '\r' | grep "^$SUF:" | cut -d: -f2)
        echo
        if [ -n "$VECES" ]; then
            echo "HIBP: ¡aparece $VECES veces en filtraciones! No la uses."
        else
            echo "HIBP: no aparece en filtraciones conocidas."
        fi
    else
        echo
        echo "HIBP: no se pudo consultar (¿sin conexión?)."
    fi
fi
