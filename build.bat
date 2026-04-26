@echo off
REM LAMIS Build Script - Creates onedir executable with bundled resources
REM Usage: build.bat [--clean] [--sign <path_to_cert.pfx>]
REM
REM Examples:
REM   build.bat                        -- Build only
REM   build.bat --clean                -- Clean old builds then build
REM   build.bat --sign cert.pfx        -- Build then sign
REM   build.bat --clean --sign cert.pfx -- Clean, build, then sign

setlocal enabledelayedexpansion

REM Use venv Python if available, otherwise fall back to system Python
if exist ".venv\Scripts\python.exe" (
    set PYTHON=.venv\Scripts\python.exe
) else (
    set PYTHON=python
)

REM Configuration
set APP_NAME=LAMIS
set ENTRY_POINT=main.py
set ICON=icon.ico
set BUILD_MODE=--onedir

REM Parse arguments
set DO_CLEAN=0
set DO_SIGN=0
set CERT_FILE=

:parse_args
if "%1"=="--clean" (
    set DO_CLEAN=1
    shift
    goto parse_args
)
if "%1"=="--sign" (
    set DO_SIGN=1
    set CERT_FILE=%2
    shift
    shift
    goto parse_args
)

REM Check for clean flag
if "%DO_CLEAN%"=="1" (
    echo Cleaning previous builds...
    if exist dist (
        rmdir /s /q dist
        echo Cleaned dist folder
    )
    if exist build (
        rmdir /s /q build
        echo Cleaned build folder
    )
    if exist %APP_NAME%.spec (
        del %APP_NAME%.spec
        echo Deleted spec file
    )
)

REM Verify dependencies
echo.
echo [*] Checking dependencies...
%PYTHON% -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo [!] PyInstaller not found. Installing...
    %PYTHON% -m pip install pyinstaller
)

REM Verify data files exist
echo [*] Verifying data files...
if not exist "L.A.M.I.S Logo.png" (
    echo [!] ERROR: L.A.M.I.S Logo.png not found
    exit /b 1
)
if not exist "data\LAMIS_Packing_Slip.xlsx" (
    echo [!] ERROR: data\LAMIS_Packing_Slip.xlsx not found
    exit /b 1
)
if not exist "data\LAMIS_Consolidated_Packing_Slip.xlsx" (
    echo [!] ERROR: data\LAMIS_Consolidated_Packing_Slip.xlsx not found
    exit /b 1
)
if not exist "data\Device_Report_Template.xlsx" (
    echo [!] ERROR: data\Device_Report_Template.xlsx not found
    exit /b 1
)
echo [OK] All data files found

REM Build command with all necessary options
echo.
echo [*] Building %APP_NAME% executable (this may take 1-2 minutes)...
echo.

if exist "%ICON%" (
    echo Using icon: %ICON%
    %PYTHON% -m PyInstaller %BUILD_MODE% --windowed --name "%APP_NAME%" ^
        --add-data "L.A.M.I.S Logo.png:." ^
        --add-data "data:data" ^
        --collect-all paramiko ^
        --collect-all openpyxl ^
        --collect-all pandas ^
        --collect-all PIL ^
        --icon "%ICON%" ^
        %ENTRY_POINT%
) else (
    echo [!] WARNING: icon.ico not found - building without icon
    %PYTHON% -m PyInstaller %BUILD_MODE% --windowed --name "%APP_NAME%" ^
        --add-data "L.A.M.I.S Logo.png:." ^
        --add-data "data:data" ^
        --collect-all paramiko ^
        --collect-all openpyxl ^
        --collect-all pandas ^
        --collect-all PIL ^
        %ENTRY_POINT%
)

if errorlevel 1 (
    echo [!] Build failed
    exit /b 1
)

echo.
echo [OK] Build completed successfully!
echo Output: dist\%APP_NAME%\%APP_NAME%.exe

REM Optionally sign the executable before packaging
if "%DO_SIGN%"=="1" (
    if "%CERT_FILE%"=="" (
        echo [!] --sign requires a certificate path: build.bat --sign cert.pfx
        exit /b 1
    )
    echo.
    echo [*] Signing executable...
    call sign.bat "%CERT_FILE%" --exe-only
    if errorlevel 1 (
        echo [!] Signing failed - aborting installer build
        exit /b 1
    )
)

REM Build installer
echo.
echo [*] Building installer (requires NSIS)...
makensis LAMIS.nsi >nul 2>&1
if errorlevel 1 (
    echo [!] WARNING: makensis not found or failed - skipping installer build
    echo     Install NSIS: choco install nsis -y
    echo     Then run: makensis LAMIS.nsi
) else (
    echo [OK] Installer built: dist\LAMIS_Setup.exe

    REM Sign the installer too
    if "%DO_SIGN%"=="1" (
        echo [*] Signing installer...
        call sign.bat "%CERT_FILE%" --installer-only
        if errorlevel 1 (
            echo [!] Installer signing failed
            exit /b 1
        )
    )
)

echo.
echo ============================================
echo Build Summary
echo ============================================
echo Executable : dist\%APP_NAME%\%APP_NAME%.exe
if exist dist\LAMIS_Setup.exe (
    echo Installer  : dist\LAMIS_Setup.exe
)
if "%DO_SIGN%"=="1" (
    echo Signed     : YES
) else (
    echo Signed     : NO (run: build.bat --sign cert.pfx)
)
echo ============================================
echo.

endlocal
