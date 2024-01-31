!include "MUI.nsh"

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Name "Stonenet"
OutFile "stonenet-installer.exe"
InstallDir "$PROGRAMFILES\Stonenet"
ShowInstDetails show

Section "Stonenet"
  SetOutPath - 
  File "../target/x86_64-pc-windows-gnu/release/stonenetd.exe"
  File /r ../static
  File /r ../templates
  File /oname=config.toml ../conf/default.toml
SectionEnd