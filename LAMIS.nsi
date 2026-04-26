; LAMIS Installer Script (NSIS)
; Install script for LAMIS (Lightriver Automated Multivendor Inventory System)
; To build: makensis LAMIS.nsi
; Output: dist\LAMIS_Setup.exe

!include "MUI2.nsh"
!include "x64.nsh"

; Basic Settings
Name "LAMIS"
OutFile "dist\LAMIS_Setup.exe"
InstallDir "$PROGRAMFILES\LAMIS"
InstallDirRegKey HKCU "Software\LAMIS" ""

; Request admin privileges on Windows Vista+
RequestExecutionLevel admin

; MUI Settings
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; Version Info
VIProductVersion "1.0.0.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "LAMIS"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "1.0.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "Lightriver Technologies"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "Network Inventory System"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "1.0.0"

; Installation section
Section "Install LAMIS"
    ; Set output path to installation directory
    SetOutPath "$INSTDIR"
    
    ; Copy all files from dist/LAMIS folder (onedir output)
    File /r "dist\LAMIS\*.*"
    
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\LAMIS"
    CreateShortCut "$SMPROGRAMS\LAMIS\LAMIS.lnk" "$INSTDIR\LAMIS.exe" "" "$INSTDIR\LAMIS.exe" 0
    CreateShortCut "$SMPROGRAMS\LAMIS\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
    CreateShortCut "$DESKTOP\LAMIS.lnk" "$INSTDIR\LAMIS.exe" "" "$INSTDIR\LAMIS.exe" 0
    
    ; Write registry keys
    WriteRegStr HKCU "Software\LAMIS" "" "$INSTDIR"
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAMIS" "DisplayName" "LAMIS"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAMIS" "DisplayVersion" "1.0.0"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAMIS" "UninstallString" "$INSTDIR\uninstall.exe"
    
    SetAutoClose true
SectionEnd

; Uninstallation section
Section "Uninstall"
    ; Remove installed files
    RMDir /r "$INSTDIR"
    
    ; Remove shortcuts
    RMDir /r "$SMPROGRAMS\LAMIS"
    Delete "$DESKTOP\LAMIS.lnk"
    
    ; Remove registry keys
    DeleteRegKey HKCU "Software\LAMIS"
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\LAMIS"
    
    SetAutoClose true
SectionEnd
