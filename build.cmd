@echo off
rem DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
rem Configure and build DnSpySql (Release) with MSVC + Ninja into .\build, then regenerate docs\SCHEMA.md
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo MSVC build tools not found & exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cmake -S "%~dp0." -B "%~dp0build" -G Ninja -DCMAKE_BUILD_TYPE=Release || exit /b 1
cmake --build "%~dp0build" %* || exit /b 1
"%~dp0build\dnspysql.exe" --schema-md > "%~dp0docs\SCHEMA.md" || exit /b 1
