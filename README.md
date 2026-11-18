# Password Verification

Analizador de fortaleza de contraseñas en una sola línea de comando. Sin dependencias, 100 % local.

## Qué hace
Estima la entropía (bits) según longitud y tipos de caracteres.
Detecta contraseñas comunes, repeticiones, secuencias (1234, qwer) y patrones tipo Palabra123!.
Opcional (--hibp): comprueba si ha aparecido en filtraciones con Have I Been Pwned usando k-anonymity: solo se envían los 5 primeros caracteres del hash SHA-1, nunca la contraseña.

Esta herramienta está disponible en 3 lenguajes disponibles 
- Bash
- Python
- PowerShell

## Uso 

### Python
```python
python3 PassVerify.py            # Análisis local
python3 PassVerify.py --hibp     # Comprobación de filtraciones
```

### console
```bash
./PassVerify.sh               # Análisis local
./PassVerify.sh --hibp        # Comprobación de filtraciones
```

### powershell
```ps1
.\PassVerify.ps1              # Análisis local
.\PassVerify.ps1 -Hibp        # Comprobación de filtraciones
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

La licencia MIT es una licencia de software libre permisiva creada por el MIT que permite usar, copiar, modificar y distribuir software, incluso con fines comerciales, con la única obligación de mantener el aviso de copyright y la licencia original.

#### Definición
La licencia MIT es una licencia de software libre y de código abierto muy flexible. Permite usar, modificar, vender y redistribuir el software sin restricciones significativas, siempre que se conserve el aviso de derechos de autor y el texto de la licencia.
