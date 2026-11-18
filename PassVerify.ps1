<#
.SYNOPSIS
    PassVerify.ps1: analizador de fortaleza de contraseñas (PowerShell 5.1 y 7+).
.DESCRIPTION
    Local y sin dependencias. Con -Hibp consulta Have I Been Pwned usando
    k-anonymity (solo se envían 5 caracteres del hash SHA-1).
.EXAMPLE
    .\PassVerify.ps1
    .\PassVerify.ps1 -Hibp
#>
param([switch]$Hibp)

$secure = Read-Host 'Contraseña (no se mostrará)' -AsSecureString
$pw = [System.Net.NetworkCredential]::new('', $secure).Password
if ([string]::IsNullOrEmpty($pw)) { Write-Error 'No has introducido nada.'; exit 1 }

$len    = $pw.Length
$low    = $pw.ToLower()
$avisos = New-Object System.Collections.Generic.List[string]
$factor = 100
$tope   = 0

# Alfabeto estimado
$alfa = 0
if ($pw -cmatch '[a-z]')          { $alfa += 26 }
if ($pw -cmatch '[A-Z]')          { $alfa += 26 }
if ($pw -match  '\d')             { $alfa += 10 }
if ($pw -match  '[^\p{L}\p{N}]')  { $alfa += 32 }

if ($len -lt 12) { $avisos.Add('Menos de 12 caracteres: alárgala.') }

$comunes = @('123456','123456789','12345678','password','qwerty','abc123','111111',
    '123123','admin','letmein','welcome','iloveyou','contraseña','contrasena',
    'password1','qwerty123','000000','dragon','football','monkey','master',
    'login','1234','12345')
if ($comunes -contains $low) {
    $avisos.Add('Es una de las contraseñas más usadas.')
    $tope = 10
}

if ($pw -match '(.)\1\1') {
    $avisos.Add('Tiene caracteres repetidos (aaa, 111...).')
    $factor = [math]::Floor($factor * 80 / 100)
}

function Test-Secuencia([string]$texto) {
    foreach ($seq in 'abcdefghijklmnopqrstuvwxyz','qwertyuiop','asdfghjkl','zxcvbnm','0123456789') {
        for ($i = 0; $i -le $seq.Length - 4; $i++) {
            $t = $seq.Substring($i, 4)
            $chars = $t.ToCharArray(); [array]::Reverse($chars)
            $r = -join $chars
            if ($texto.Contains($t) -or $texto.Contains($r)) { return $true }
        }
    }
    return $false
}
if (Test-Secuencia $low) {
    $avisos.Add('Contiene secuencias previsibles (abcd, 1234, qwer...).')
    $factor = [math]::Floor($factor * 80 / 100)
}

if ($pw -match '^[A-Za-z]+\d{1,4}[!@#$%^&*.]?$') {
    $avisos.Add("Patrón típico 'Palabra123!': fácil de adivinar.")
    $factor = [math]::Floor($factor * 70 / 100)
}

# Entropía
$bits = 0.0
if ($alfa -gt 0) { $bits = $len * [math]::Log($alfa, 2) }
if ($tope -gt 0 -and $bits -gt $tope) { $bits = $tope }
$bits = [math]::Round($bits * $factor / 100, 1)

$nivel = switch ($bits) {
    { $_ -lt 40 }  { 'MUY DÉBIL'; break }
    { $_ -lt 60 }  { 'DÉBIL'; break }
    { $_ -lt 80 }  { 'ACEPTABLE'; break }
    { $_ -lt 100 } { 'FUERTE'; break }
    default        { 'MUY FUERTE' }
}

''
"Longitud : $len"
"Entropía : ~$($bits.ToString([cultureinfo]::InvariantCulture)) bits"
"Nivel    : $nivel"
foreach ($a in $avisos) { "  ! $a" }

# Have I Been Pwned (k-anonymity)
if ($Hibp) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $sha  = [System.Security.Cryptography.SHA1]::Create()
        $hash = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($pw)) |
                 ForEach-Object { $_.ToString('X2') }) -join ''
        $pre, $suf = $hash.Substring(0, 5), $hash.Substring(5)
        $resp = Invoke-RestMethod -Uri "https://api.pwnedpasswords.com/range/$pre" `
                    -UserAgent 'passcheck-educational' -TimeoutSec 8
        $linea = ($resp -split "`r?`n") | Where-Object { $_ -like "${suf}:*" } | Select-Object -First 1
        ''
        if ($linea) { "HIBP: ¡aparece $($linea.Split(':')[1]) veces en filtraciones! No la uses." }
        else        { 'HIBP: no aparece en filtraciones conocidas.' }
    } catch {
        ''
        'HIBP: no se pudo consultar (¿sin conexión?).'
    }
}
