; HashGuard Windows Installer
; Built with NSIS (Nullsoft Scriptable Install System)
; Licensed under Elastic License 2.0 (ELv2)

;=============================================================================
; Configuration
;=============================================================================
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!include "WordFunc.nsh"

; Product Details
!ifndef VERSION
  !define VERSION "1.1.2"
!endif
!ifndef DISTDIR
  !define DISTDIR "dist\HashGuard"
!endif
Name "HashGuard v${VERSION}"
OutFile "HashGuard-App-${VERSION}.exe"
InstallDir "$LOCALAPPDATA\HashGuard"
InstallDirRegKey HKCU "Software\HashGuard" "InstallDir"
RequestExecutionLevel user

; UI Configuration
!define MUI_ABORTWARNING
!define MUI_ICON "hashguard.ico"
!define MUI_UNICON "hashguard.ico"

; MUI2 Page definitions
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_REBOOTLATER_DEFAULT
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; Version Info
VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "HashGuard"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "HashGuard"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "File Analysis & Malware Detection"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "Copyright (c) 2026 Alberto Tijunelis Neto. Elastic License 2.0."

;=============================================================================
; Sections
;=============================================================================

Section "HashGuard Application (Required)" SecMain
    SectionIn RO
    
    SetOutPath "$INSTDIR"
    SetOverwrite on
    
    ; Install all files from the merged distribution directory.
    ; With --onedir builds the EXEs and their dependencies are separate
    ; files, which avoids AV false positives from packed/self-extracting
    ; executables.
    File /r "${DISTDIR}\*.*"
    
    ; Create Start Menu entry
    CreateDirectory "$SMPROGRAMS\HashGuard"
    CreateShortcut "$SMPROGRAMS\HashGuard\HashGuard CLI.lnk" "$INSTDIR\hashguard.exe" "" "$INSTDIR\hashguard.exe" 0
    
    ; Registry entries
    WriteRegStr HKCU "Software\HashGuard" "InstallDir" "$INSTDIR"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HashGuard" "DisplayName" "HashGuard"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HashGuard" "DisplayVersion" "${VERSION}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HashGuard" "Publisher" "HashGuard"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HashGuard" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HashGuard" "InstallLocation" "$INSTDIR"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HashGuard" "DisplayIcon" "$INSTDIR\hashguard.exe"
    
SectionEnd

Section "Documentation" SecDocs
    
    SetOutPath "$INSTDIR\docs"
    File ..\LICENSE
    File ..\README.md
    File ..\CHANGELOG.md
    
    ; Create Start Menu shortcut to docs
    CreateShortcut "$SMPROGRAMS\HashGuard\Documentation.lnk" "$INSTDIR\docs\README.md"
    
SectionEnd

Section "Add to PATH (Advanced)" SecPath
    
    ; Add installation directory to user PATH for CLI access
    ReadRegStr $0 HKCU "Environment" "PATH"
    StrCmp $0 "" _pathEmpty _pathExists
    _pathEmpty:
        WriteRegStr HKCU "Environment" "PATH" "$INSTDIR"
        Goto _pathDone
    _pathExists:
        WriteRegStr HKCU "Environment" "PATH" "$0;$INSTDIR"
    _pathDone:
    
SectionEnd

Section "Uninstall"
    
    ; Remove entire installation directory (all PyInstaller output files)
    RMDir /r "$INSTDIR"
    
    ; Remove Start Menu
    RMDir /r "$SMPROGRAMS\HashGuard"
    
    ; Remove from user PATH
    ReadRegStr $0 HKCU "Environment" "PATH"
    ${If} $0 != ""
        ; Remove $INSTDIR from PATH (with and without trailing semicolon)
        ${WordReplace} $0 ";$INSTDIR" "" "+" $0
        ${WordReplace} $0 "$INSTDIR;" "" "+" $0
        ${WordReplace} $0 "$INSTDIR" "" "+" $0
        WriteRegStr HKCU "Environment" "PATH" "$0"
    ${EndIf}

    ; Remove registry entries
    DeleteRegKey HKCU "Software\HashGuard"
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HashGuard"
    
SectionEnd

;=============================================================================
; Component Descriptions
;=============================================================================

LangString DESC_SecMain ${LANG_ENGLISH} "HashGuard CLI, web dashboard, and analysis engine"
LangString DESC_SecDocs ${LANG_ENGLISH} "Documentation and usage guides"
LangString DESC_SecPath ${LANG_ENGLISH} "Add HashGuard CLI to system PATH for command-line access (for advanced users)"

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} $(DESC_SecMain)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDocs} $(DESC_SecDocs)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} $(DESC_SecPath)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;=============================================================================
; Installer Initialization
;=============================================================================

Function .onInit
    
    ; Kill any running HashGuard processes
    nsExec::ExecToStack 'cmd /c taskkill /F /IM hashguard.exe 2>nul'
    Pop $0
    Pop $0
    Sleep 500
    
    ; Check if already installed
    ReadRegStr $0 HKCU "Software\HashGuard" "InstallDir"
    ${If} $0 != ""
        MessageBox MB_YESNO "HashGuard is already installed at:$\n$0$\n$\nDo you want to reinstall?" IDYES ProceedInstall
        Abort
        ProceedInstall:
    ${EndIf}
    
FunctionEnd

Function un.onInit
    
    MessageBox MB_YESNO "Are you sure you want to completely remove HashGuard and all its components?" IDYES +2
    Abort
    
FunctionEnd

;=============================================================================
; Function: Create Uninstaller
;=============================================================================

Section -CreateUninstaller
    
    WriteUninstaller "$INSTDIR\uninstall.exe"
    
    CreateShortcut "$SMPROGRAMS\HashGuard\Uninstall.lnk" "$INSTDIR\uninstall.exe"
    
SectionEnd
