!include "MUI.nsh"
!include "x64.nsh"

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "../LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Create Desktop Shortcut"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION "CreateDesktopShortcut"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Launch the Stonenet daemon"
!define MUI_FINISHPAGE_RUN_FUNCTION "StartStonenet"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Section "Initialize"
	SetRegView 64
SectionEnd


Name "Stonenet"
OutFile "stonenet-installer.exe"
ShowInstDetails show
InstallDir "$PROGRAMFILES64\Stonenet"
InstallDirRegKey HKLM Software\Stonenet InstallDir


Section "Stonenet"
	SetOutPath - 

	ExecWait 'taskkill /f /t /im stonenetd.exe'

	WriteRegStr HKLM Software\Stonenet InstallDir "$INSTDIR"

	File "../target/x86_64-pc-windows-gnu/release/stonenetd.exe"
	File "../target/x86_64-pc-windows-gnu/release/stonenet-desktop.exe"
	File "../target/x86_64-pc-windows-gnu/release/WebView2Loader.dll"
	File /r ../static
	File /r ../templates
	File /oname=config.toml ../conf/default-system.toml

	# Pre-create directory for Edge WebView2 framework to use
	CreateDirectory "$INSTDIR\stonenet-desktop.exe.WebView2"
	ExecWait 'icacls "$INSTDIR\stonenet-desktop.exe.WebView2" /grant Users:F'

	WriteUninstaller $INSTDIR\uninstaller.exe
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Stonenet" "DisplayName" "Stonenet"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Stonenet" "UninstallString" '"$INSTDIR\uninstaller.exe"'

	# Place a file for the sqlite database if it doens't exist yet
	SetOverwrite off
	File /oname=db.sqlite ../assets/empty.sqlite

	CreateDirectory "$SMPROGRAMS\Stonenet"
	CreateShortcut "$DESKTOP\Stonenet.lnk" "$INSTDIR\stonenet-desktop.exe"

	WriteRegStr HKLM Software\Microsoft\Windows\CurrentVersion\Run StonenetDaemon '"$INSTDIR\stonenetd.exe"'
	# Remove 32-bit autorun entry for previous installs.
	DeleteRegValue HKLM "Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" "StonenetDaemon"
SectionEnd

Section "Uninstall"
	RmDir /r "$INSTDIR"
SectionEnd

Function CreateDesktopShortcut
	CreateShortcut "$DESKTOP\Stonenet.lnk" "$INSTDIR\stonenet-desktop.exe"
FunctionEnd

Function StartStonenet
	Exec '"$INSTDIR\stonenetd.exe"'
FunctionEnd
