# Password Verification

Analizador de fortaleza de contraseñas en una sola línea de comando. Sin dependencias, 100 % local.

## Qué hace
Estima la entropía (bits) según longitud y tipos de caracteres.
Detecta contraseñas comunes, repeticiones, secuencias (1234, qwer) y patrones tipo Palabra123!.
Opcional (--hibp): comprueba si ha aparecido en filtraciones con Have I Been Pwned usando k-anonymity: solo se envían los 5 primeros caracteres del hash SHA-1, nunca la contraseña.

Esta herramienta está disponible en 3 lenguajes disponibles (bash, Python, PowerShell).

## Uso

### Python
```python
python PassVerify.py          # análisis local
python PassVerify.py --hibp   # + comprobación de filtraciones
```

### console
```bash
./PassVerify.sh               # análisis local
./PassVerify.sh --hibp        # + comprobación de filtraciones
```

### powershell
```ps1
.\PassVerify.ps1        # análisis local
.\PassVerify.ps1 -Hibp  # + comprobación de filtraciones
```

La contraseña se pide con getpass, así que no queda en pantalla ni en el historial de la shell.

## Limitaciones

La entropía es una estimación, no una garantía. Usa un gestor de contraseñas y 2FA.

## Imagenes

### Python


### Bash


### PowerShell



## Licencia

MIT
