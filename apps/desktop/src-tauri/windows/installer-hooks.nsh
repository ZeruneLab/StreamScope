!ifndef STREAMSCOPE_LOADER_DIR
  !define STREAMSCOPE_LOADER_DIR "${__FILEDIR__}\..\..\..\..\target\release"
!endif

!macro NSIS_HOOK_POSTINSTALL
  SetOutPath "$INSTDIR"
  File /oname=WebView2Loader.dll "${STREAMSCOPE_LOADER_DIR}\WebView2Loader.dll"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Delete "$INSTDIR\WebView2Loader.dll"
!macroend
