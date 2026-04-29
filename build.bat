@echo off
REM ATLAS Build Script - Creates onedir executable with bundled resources
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
set APP_NAME=ATLAS
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
if not exist "ATLAS Logo.png" (
    echo [!] ERROR: ATLAS Logo.png not found
    exit /b 1
)
if not exist "data\ATLAS_Packing_Slip.xlsx" (
    echo [!] ERROR: data\ATLAS_Packing_Slip.xlsx not found
    exit /b 1
)
if not exist "data\ATLAS_Consolidated_Packing_Slip.xlsx" (
    echo [!] ERROR: data\ATLAS_Consolidated_Packing_Slip.xlsx not found
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
        --add-data "ATLAS Logo.png:." ^
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
        --add-data "ATLAS Logo.png:." ^
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
where makensis >nul 2>&1
if not errorlevel 1 goto :invoke_nsis_system
if exist "C:\Program Files (x86)\NSIS\makensis.exe" goto :invoke_nsis_x86
if exist "C:\Program Files\NSIS\makensis.exe" goto :invoke_nsis_x64
echo [!] NSIS not found - install NSIS and add to PATH, or install to default location.
exit /b 1

:invoke_nsis_x86
"C:\Program Files (x86)\NSIS\makensis.exe" ATLAS.nsi
goto :nsis_check

:invoke_nsis_x64
"C:\Program Files\NSIS\makensis.exe" ATLAS.nsi
goto :nsis_check

:invoke_nsis_system
makensis ATLAS.nsi

:nsis_check
if errorlevel 1 (
    echo [!] NSIS build failed
    exit /b 1
)

echo [OK] Installer built: dist\ATLAS_Setup.exe

REM Sign the installer too
if "%DO_SIGN%"=="1" (
    echo [*] Signing installer...
    call sign.bat "%CERT_FILE%" --installer-only
    if errorlevel 1 (
        echo [!] Installer signing failed
        exit /b 1
    )
)

REM Remove standalone executable - keep ONLY the Setup.exe as final deliverable
echo [*] Cleaning up intermediate artifacts...
if exist "dist\%APP_NAME%\%APP_NAME%.exe" (
    del "dist\%APP_NAME%\%APP_NAME%.exe"
    echo [OK] Removed standalone executable
)
if exist "dist\%APP_NAME%" (
    rmdir /s /q "dist\%APP_NAME%"
    echo [OK] Removed build intermediate folder
)

echo.
echo ============================================
echo Build Summary
echo ============================================
if exist dist\ATLAS_Setup.exe (
    echo Final Deliverable: dist\ATLAS_Setup.exe
) else (
    echo Executable : dist\%APP_NAME%\%APP_NAME%.exe
)
if "%DO_SIGN%"=="1" (
    echo Signed     : YES
) else (
    echo Signed     : NO (run: build.bat --sign cert.pfx)
)
echo ============================================
echo.

endlocal
