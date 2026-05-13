# archefot_crypto.ps1 - shared AES-256 helpers for .archkey files
#
# File format (.archkey):
#   Bytes  0-15 : salt   (random, 16 B)
#   Bytes 16-31 : IV     (random, 16 B)
#   Bytes 32+   : AES-256-CBC ciphertext of the 26-char cipher alphabet
#
# Key derivation: PBKDF2-SHA256, 100000 iterations, 32-byte key.

Add-Type -AssemblyName System.Security

function Protect-Legend {
    param(
        [string]$Alphabet,
        [string]$Password,
        [string]$OutPath
    )

    $salt = New-Object byte[] 16
    $iv   = New-Object byte[] 16
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($salt)
    $rng.GetBytes($iv)

    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $Password, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $kdf.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key     = $key
    $aes.IV      = $iv

    $enc        = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Alphabet)
    $cipherBytes = $enc.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

    $blob = New-Object byte[] (16 + 16 + $cipherBytes.Length)
    [Array]::Copy($salt,        0, $blob, 0,  16)
    [Array]::Copy($iv,          0, $blob, 16, 16)
    [Array]::Copy($cipherBytes, 0, $blob, 32, $cipherBytes.Length)

    [System.IO.File]::WriteAllBytes($OutPath, $blob)

    $aes.Dispose(); $kdf.Dispose(); $rng.Dispose()
}

function Unprotect-Legend {
    param(
        [string]$Path,
        [string]$Password
    )

    $blob = [System.IO.File]::ReadAllBytes($Path)
    if ($blob.Length -lt 33) { throw "Invalid .archkey file." }

    $salt = $blob[0..15]
    $iv   = $blob[16..31]
    $cipherBytes = $blob[32..($blob.Length - 1)]

    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $Password, [byte[]]$salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $kdf.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key     = $key
    $aes.IV      = [byte[]]$iv

    try {
        $dec = $aes.CreateDecryptor()
        $plainBytes = $dec.TransformFinalBlock([byte[]]$cipherBytes, 0, $cipherBytes.Length)
        $alphabet = [System.Text.Encoding]::UTF8.GetString($plainBytes)
    } catch {
        $aes.Dispose(); $kdf.Dispose()
        throw "Wrong password or corrupted key file."
    }

    $aes.Dispose(); $kdf.Dispose()

    if ($alphabet.Length -ne 36) { throw "Invalid key: expected 36 characters, got $($alphabet.Length)." }
    $sorted = ($alphabet.ToCharArray() | Sort-Object) -join ''
    if ($sorted -ne '0123456789abcdefghijklmnopqrstuvwxyz') { throw "Invalid key: not a permutation of a-z0-9." }

    return $alphabet
}