; ATLAS Installer Script (NSIS)
; Install script for ATLAS (Automated Toolkit for Lightriver Asset & Systems)
; To build: makensis ATLAS.nsi
; Output: dist\ATLAS_Setup.exe

!include "MUI2.nsh"
!include "x64.nsh"

; Basic Settings
Name "ATLAS"
OutFile "dist\ATLAS_Setup.exe"
InstallDir "$PROGRAMFILES\ATLAS"
InstallDirRegKey HKCU "Software\ATLAS" ""
Icon "icon.ico"
UninstallIcon "icon.ico"

; Request admin privileges on Windows Vista+
RequestExecutionLevel admin

; MUI Settings
!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; Version Info
VIProductVersion "1.0.0.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "ATLAS"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "1.0.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "Lightriver Technologies"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "Automated Toolkit for Lightriver Asset & Systems"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "1.0.0"

; Installation section
Section "Install ATLAS"
    ; Set output path to installation directory
    SetOutPath "$INSTDIR"
    
    ; Copy all files from dist/ATLAS folder (onedir output)
    File /r "dist\ATLAS\*.*"
    
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\ATLAS"
    CreateShortCut "$SMPROGRAMS\ATLAS\ATLAS.lnk" "$INSTDIR\ATLAS.exe" "" "$INSTDIR\ATLAS.exe" 0
    CreateShortCut "$SMPROGRAMS\ATLAS\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
    CreateShortCut "$DESKTOP\ATLAS.lnk" "$INSTDIR\ATLAS.exe" "" "$INSTDIR\ATLAS.exe" 0
    
    ; Write registry keys
    WriteRegStr HKCU "Software\ATLAS" "" "$INSTDIR"
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ATLAS" "DisplayName" "ATLAS"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ATLAS" "DisplayVersion" "1.0.0"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ATLAS" "UninstallString" "$INSTDIR\uninstall.exe"
    
    SetAutoClose true
SectionEnd

; Uninstallation section
Section "Uninstall"
    ; Remove installed files
    RMDir /r "$INSTDIR"
    
    ; Remove shortcuts
    RMDir /r "$SMPROGRAMS\ATLAS"
    Delete "$DESKTOP\ATLAS.lnk"
    
    ; Remove registry keys
    DeleteRegKey HKCU "Software\ATLAS"
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ATLAS"
    
    SetAutoClose true
SectionEnd
