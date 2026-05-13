@echo off
setlocal

:: ============================================================
::  ARCHEFOT CIPHER  -  Drag a .txt file onto this .bat
:: ============================================================

if "%~1"=="" (
    echo.
    echo   ERROR: No file provided.
    echo   Drag a .txt file onto this .bat to run it.
    echo.
    pause
    exit /b 1
)

if not exist "%~1" (
    echo.
    echo   ERROR: File not found: %~1
    echo.
    pause
    exit /b 1
)

echo.
echo   ========================================
echo        A R C H E F O T   C I P H E R
echo   ========================================
echo.
echo   File: %~nx1
echo.
echo   [1] Normal  --^>  Archefot  (encrypt)
echo   [2] Archefot --^>  Normal   (decrypt)
echo.
set /p "MODE=   Choose [1/2]: "

if "%MODE%"=="1" (
    set "DIR=encrypt"
) else if "%MODE%"=="2" (
    set "DIR=decrypt"
) else (
    echo.
    echo   Invalid choice.
    pause
    exit /b 1
)

set "OUTFILE=%~dpn1_archefot%~x1"

:: Hand off to PowerShell for the actual cipher work
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "$plain = 'abcdefghijklmnopqrstuvwxyz';" ^
 "$cipher = 'qwertyuiopasdfghjklzxcvbnm';" ^
 "$dir = '%DIR%';" ^
 "$inFile = '%~1';" ^
 "$outFile = '%OUTFILE%';" ^
 "if ($dir -eq 'encrypt') { $from = $plain; $to = $cipher }" ^
 "else { $from = $cipher; $to = $plain };" ^
 "$map = @{};" ^
 "for ($i = 0; $i -lt 26; $i++) {" ^
 "  $map[[string]$from[$i]] = [string]$to[$i];" ^
 "  $map[[string]([char]::ToUpper($from[$i]))] = [string]([char]::ToUpper($to[$i]));" ^
 "};" ^
 "$lines = [System.IO.File]::ReadAllLines($inFile);" ^
 "$result = foreach ($line in $lines) {" ^
 "  $sb = [System.Text.StringBuilder]::new($line.Length);" ^
 "  foreach ($c in $line.ToCharArray()) {" ^
 "    $key = [string]$c;" ^
 "    if ($map.ContainsKey($key)) { [void]$sb.Append($map[$key]) }" ^
 "    else { [void]$sb.Append($c) }" ^
 "  };" ^
 "  $sb.ToString();" ^
 "};" ^
 "[System.IO.File]::WriteAllLines($outFile, $result);"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo   ERROR: Processing failed.
    pause
    exit /b 1
)

if "%DIR%"=="encrypt" (
    echo.
    echo   ENCRYPTED successfully!
) else (
    echo.
    echo   DECRYPTED successfully!
)

echo   Output: %OUTFILE%
echo.
pause
exit /b 0