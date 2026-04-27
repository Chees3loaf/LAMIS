@echo off
REM LAMIS Code Signing Script
REM Signs the LAMIS executable and/or installer with a code signing certificate.
REM
REM Usage:
REM   sign.bat <cert.pfx>                  -- Sign both exe and installer
REM   sign.bat <cert.pfx> --exe-only       -- Sign executable only
REM   sign.bat <cert.pfx> --installer-only -- Sign installer only
REM
REM Requires: Windows SDK (signtool.exe)
REM   Install: choco install windows-sdk -y
REM   Or download Visual Studio Build Tools from https://aka.ms/buildtools

setlocal enabledelayedexpansion

REM --- Parse arguments ---
set CERT_FILE=%1
set MODE=both
if "%2"=="--exe-only"       set MODE=exe
if "%2"=="--installer-only" set MODE=installer

if "%CERT_FILE%"=="" (
    echo.
    echo Usage: sign.bat ^<path_to_certificate.pfx^> [--exe-only ^| --installer-only]
    echo.
    echo Examples:
    echo   sign.bat "certs\LightRiver_codesign.pfx"
    echo   sign.bat "certs\LightRiver_codesign.pfx" --exe-only
    echo   sign.bat "certs\LightRiver_codesign.pfx" --installer-only
    echo.
    exit /b 1
)

REM --- Verify certificate exists ---
if not exist "%CERT_FILE%" (
    echo [!] ERROR: Certificate not found: %CERT_FILE%
    exit /b 1
)

REM --- Find signtool ---
REM Try PATH first
signtool /? >nul 2>&1
if errorlevel 1 (
    REM Try common Windows SDK locations
    set SIGNTOOL=
    for %%d in (
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe"
        "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
    ) do (
        if exist %%d set SIGNTOOL=%%d
    )
    if "!SIGNTOOL!"=="" (
        echo [!] ERROR: signtool.exe not found
        echo.
        echo Install Windows SDK:
        echo   choco install windows-sdk -y
        echo   or download: https://aka.ms/buildtools
        echo.
        exit /b 1
    )
) else (
    set SIGNTOOL=signtool
)

REM --- Certificate password ---
set /p CERT_PASSWORD="Enter certificate password: "

REM --- Timestamp server ---
REM Using DigiCert's timestamp server (SHA-256, long-lived)
set TIMESTAMP_SERVER=http://timestamp.digicert.com

REM --- Publisher info ---
set PUBLISHER_DESC=LAMIS - Lightriver Automated Multivendor Inventory System
set PUBLISHER_URL=https://www.lightrivertechnologies.com

REM --- Sign executable ---
if "%MODE%"=="both" goto :sign_exe
if "%MODE%"=="exe" goto :sign_exe
goto :sign_installer

:sign_exe
if not exist "dist\LAMIS\LAMIS.exe" (
    echo [!] ERROR: dist\LAMIS\LAMIS.exe not found - run build.bat first
    exit /b 1
)
echo [*] Signing dist\LAMIS\LAMIS.exe...
%SIGNTOOL% sign ^
  /f "%CERT_FILE%" ^
  /p "%CERT_PASSWORD%" ^
  /fd SHA256 ^
  /tr "%TIMESTAMP_SERVER%" ^
  /td SHA256 ^
  /d "%PUBLISHER_DESC%" ^
  /du "%PUBLISHER_URL%" ^
  dist\LAMIS\LAMIS.exe
if errorlevel 1 (
    echo [!] Failed to sign LAMIS.exe
    exit /b 1
)
echo [OK] LAMIS.exe signed
if "%MODE%"=="exe" goto :verify

REM --- Sign installer ---
:sign_installer
if not exist "dist\LAMIS_Setup.exe" (
    echo [!] ERROR: dist\LAMIS_Setup.exe not found - run makensis LAMIS.nsi first
    exit /b 1
)
echo [*] Signing dist\LAMIS_Setup.exe...
%SIGNTOOL% sign ^
  /f "%CERT_FILE%" ^
  /p "%CERT_PASSWORD%" ^
  /fd SHA256 ^
  /tr "%TIMESTAMP_SERVER%" ^
  /td SHA256 ^
  /d "%PUBLISHER_DESC%" ^
  /du "%PUBLISHER_URL%" ^
  dist\LAMIS_Setup.exe
if errorlevel 1 (
    echo [!] Failed to sign LAMIS_Setup.exe
    exit /b 1
)
echo [OK] LAMIS_Setup.exe signed

REM --- Verify signatures ---
:verify
echo.
echo [*] Verifying signatures...
if "%MODE%"=="both" (
    %SIGNTOOL% verify /pa /v dist\LAMIS\LAMIS.exe
    %SIGNTOOL% verify /pa /v dist\LAMIS_Setup.exe
) else if "%MODE%"=="exe" (
    %SIGNTOOL% verify /pa /v dist\LAMIS\LAMIS.exe
) else (
    %SIGNTOOL% verify /pa /v dist\LAMIS_Setup.exe
)

echo.
echo [OK] Signing complete! Windows will trust these files.
echo.

endlocal

REM Verify signatures
echo.
echo [*] Verifying signatures...
signtool verify /pa dist/LAMIS/LAMIS.exe
signtool verify /pa dist/LAMIS_Setup.exe

echo.
echo [OK] All files signed successfully!
echo.
echo You can now distribute:
echo   - dist/LAMIS_Setup.exe (Windows will trust it)
echo.

endlocal
