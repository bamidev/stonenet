!include "MUI.nsh"

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
#!define MUI_FINISHPAGE_SHOWREADME ""
#!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
#!define MUI_FINISHPAGE_SHOWREADME_TEXT "Create Desktop Shortcut"
#!define MUI_FINISHPAGE_SHOWREADME_FUNCTION "CreateDesktopShortcut"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Launch the Stonenet daemon"
!define MUI_FINISHPAGE_RUN_FUNCTION "StartStonenet"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Name "Stonenet"
OutFile "stonenet-installer.exe"
ShowInstDetails show
InstallDir "$PROGRAMFILES\Stonenet"
InstallDirRegKey HKLM Software\Stonenet InstallDir


!macro CreateInternetShortcutWithIcon FILEPATH URL ICONPATH ICONINDEX
WriteINIStr "${FILEPATH}" "InternetShortcut" "URL" "${URL}"
WriteINIStr "${FILEPATH}" "InternetShortcut" "IconIndex" "${ICONINDEX}"
WriteINIStr "${FILEPATH}" "InternetShortcut" "IconFile" "${ICONPATH}"
!macroend


Section "Stonenet"
	SetOutPath - 

	ExecWait 'taskkill /f /t /im stonenetd.exe'

	WriteRegStr HKLM Software\Stonenet InstallDir "$INSTDIR"

	File "../target/x86_64-pc-windows-gnu/release/stonenetd.exe"
	File /r ../static
	File /r ../templates
	File /oname=config.toml ../conf/default.toml

	WriteRegStr HKLM Software\Microsoft\Windows\CurrentVersion\Run StonenetDaemon '"$INSTDIR\stonenetd.exe"'
SectionEnd

#Function CreateDesktopShortcut
#	CreateInternetShortcutWithIcon "$DESKTOP\Stonenet.lnk" "$windir\explorer.exe" 13
#FunctionEnd

Function StartStonenet
	Exec '"$INSTDIR\stonenetd.exe"'
FunctionEnd