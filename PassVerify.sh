#!/bin/bash
# PassVerify.sh: analizador de fortaleza de contraseñas (bash).
# Local, sin dependencias salvo utilidades estándar (awk, grep, tr; curl y sha1sum/shasum para --hibp).
# Uso: ./PassVerify.sh [--hibp | -h | -v]
#
# Última versión: ver VERSION más abajo.
#
# Historial de versiones (la más reciente arriba):
#
#    1.0.4 (2026-11-23) Se añade -v / --version para mostrar la versión del script, se corrigen colores de mensajes
#                       de salida y los avisos se muestran uno por línea con su propio '[!]'.
#    1.0.3 (2026-11-23) Se añade -h / --help con la explicación de uso. Una opción desconocida ahora muestra
#                       un error y sale con código 1 (antes se ignoraba).
#    1.0.2 (2026-11-23) Cambio estético, se añaden colores en las salidas de datos.
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
#                       nivel: de MUY DÉBIL a MUY FUERTE y consulta opcional a Have I Been Pwned (--hibp, k-anonimato).
#                       Diferentes fortalezas de contraseñas:
#                       - MUY DÉBIL
#                       - DÉBIL
#                       - ACEPTABLE
#                       - FUERTE
#                       - MUY FUERTE

VERSION="1.0.4"

# Colores (secuencias ANSI: 1 = negrita, 3X = color del texto; se interpretan con echo -e)
endColour='\e[0m'
blueColour='\e[1;34m'
greenColour='\e[1;32m'
grayColour='\e[1;37m'
purpleColour='\e[1;35m'
redColour='\e[1;31m'
yellowColour='\e[1;33m'

# Ayuda
uso() {
    echo -e "${yellowColour}PassVerify${endColour}${grayColour} - Analizador de fortaleza de contraseñas${endColour}"
    echo
    echo -e "${yellowColour}Uso:${endColour}"
    echo -e "  ${grayColour}./PassVerify.sh [opción]${endColour}"
    echo
    echo -e "${yellowColour}Opciones:${endColour}"
    echo -e "  ${blueColour}--hibp${endColour}        ${grayColour}Además del análisis local, comprueba si la contraseña aparece${endColour}"
    echo -e "                ${grayColour}en filtraciones (Have I Been Pwned). Solo se envían 5 caracteres${endColour}"
    echo -e "                ${grayColour}del hash SHA-1, nunca la contraseña. Requiere curl y conexión.${endColour}"
    echo -e "  ${blueColour}-h, --help${endColour}    ${grayColour}Muestra esta ayuda y sale.${endColour}"
    echo -e "  ${blueColour}-v, --version${endColour} ${grayColour}Muestra la versión y sale.${endColour}"
    echo
    echo -e "${yellowColour}Cómo funciona:${endColour}"
    echo -e "  ${grayColour}El script pide la contraseña por teclado (no se muestra en pantalla),${endColour}"
    echo -e "  ${grayColour}estima su entropía y la clasifica de MUY DÉBIL a MUY FUERTE.${endColour}"
    echo -e "  ${grayColour}El análisis es local: la contraseña no se guarda ni se pasa como argumento.${endColour}"
    echo
    echo -e "${yellowColour}Ejemplos:${endColour}"
    echo -e "  ${grayColour}./PassVerify.sh                  ${endColour}${purpleColour}# análisis local${endColour}"
    echo -e "  ${grayColour}./PassVerify.sh --hibp           ${endColour}${purpleColour}# + comprobación de filtraciones (Have I Been Pwned)${endColour}"
    echo -e "  ${grayColour}./PassVerify.sh -h | --help      ${endColour}${purpleColour}# Muestra esta ayuda${endColour}"
    echo -e "  ${grayColour}./PassVerify.sh -v | --version   ${endColour}${purpleColour}# Muestra la versión${endColour}"
}

HIBP=0
case "${1:-}" in
    "")           ;;
    --hibp)       HIBP=1;;
    -h|--help)    uso; exit 0;;
    -v|--version) echo "PassVerify $VERSION"; exit 0;;
    *)            echo -e "${redColour}[!] Opción desconocida: $1${endColour}" >&2
                  echo -e "${grayColour}    Usa -h para ver cómo se utiliza.${endColour}" >&2
                  exit 1;;
esac

# Leer la contraseña sin eco
echo -e "${yellowColour}[+]${endColour}${grayColour} Contraseña (no se mostrará):${endColour}" >&2
if [ -t 0 ]; then
    stty -echo
    trap 'stty echo' EXIT INT TERM
fi
IFS= read -r PW
if [ -t 0 ]; then stty echo; trap - EXIT INT TERM; fi
echo >&2

[ -n "$PW" ] || { echo -e "${redColour}[!] No has introducido nada.${endColour}" >&2; exit 1; }

LEN=${#PW}
LOW=$(printf '%s' "$PW" | tr '[:upper:]' '[:lower:]')
AVISOS=()           # lista de avisos, se muestra uno por línea
FACTOR=100          # porcentaje aplicado a la entropía
TOPE=""             # tope de entropía (contraseñas comunes)

# Alfabeto estimado
ALFA=0
case $PW in *[[:lower:]]*) ALFA=$((ALFA + 26));; esac
case $PW in *[[:upper:]]*) ALFA=$((ALFA + 26));; esac
case $PW in *[[:digit:]]*) ALFA=$((ALFA + 10));; esac
case $PW in *[[:punct:]]*) ALFA=$((ALFA + 32));; esac

# Comprobaciones
[ "$LEN" -lt 12 ] && AVISOS+=("Menos de 12 caracteres: alárgala.")

case $LOW in
    123456|123456789|12345678|9876543210|password|qwerty|abc123|111111|123123|admin|\
    letmein|welcome|iloveyou|contraseña|contrasena|password1|qwerty123|\
    000000|dragon|football|monkey|master|login|1234|12345)
        AVISOS+=("Es una de las contraseñas más usadas.")
        TOPE=10;;
esac

if printf '%s\n' "$PW" | grep -Eq '(.)\1\1'; then
    AVISOS+=("Tiene caracteres repetidos (aaa, 111...).")
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
    AVISOS+=("Contiene secuencias previsibles (abcd, 1234, qwer...).")
    FACTOR=$((FACTOR * 80 / 100))
fi

if printf '%s\n' "$PW" | grep -Eq '^[[:alpha:]]+[0-9]{1,4}[!@#$%^&*.]?$'; then
    AVISOS+=("Patrón típico 'Palabra123!': fácil de adivinar.")
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
    1) NIVEL="MUY DÉBIL";;
    2) NIVEL="DÉBIL";;
    3) NIVEL="ACEPTABLE";;
    4) NIVEL="FUERTE";;
    *) NIVEL="MUY FUERTE";;
esac

echo -e "${yellowColour}[+] ${endColour}${grayColour}Longitud :${endColour}${blueColour} $LEN${endColour}"
echo -e "${yellowColour}[+] ${endColour}${grayColour}Entropía :${endColour}${blueColour} ~$BITS bits${endColour}"
echo -e "${yellowColour}[+] ${endColour}${grayColour}Nivel    :${endColour}${blueColour} $NIVEL${endColour}"
for aviso in "${AVISOS[@]}"; do
    echo -e "${redColour}[!] ${aviso}${endColour}"
done

# Have I Been Pwned (k-anonymity)
if [ "$HIBP" -eq 1 ]; then
    if command -v sha1sum >/dev/null 2>&1; then SHA=sha1sum; else SHA="shasum -a 1"; fi
    HASH=$(printf '%s' "$PW" | $SHA | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
    PRE=$(echo "$HASH" | cut -c1-5)
    SUF=$(echo "$HASH" | cut -c6-)
    if RESP=$(curl -fsS -m 8 "https://api.pwnedpasswords.com/range/$PRE" 2>/dev/null); then
        VECES=$(echo "$RESP" | tr -d '\r' | grep "^$SUF:" | cut -d: -f2)
        echo "------"
        if [ -n "$VECES" ]; then
            echo -e "${redColour}[!] HIBP: Tu contraseña ¡aparece ${endColour}${blueColour}$VECES${endColour}${redColour} veces en filtraciones! No la uses.${endColour}"
        else
            echo -e "${yellowColour}[+] ${endColour}${greenColour}HIBP: no aparece en filtraciones conocidas.${endColour}"
        fi
    else
        echo -e "${redColour}[!] HIBP: no se pudo consultar (¿sin conexión?).${endColour}"
    fi
fi
