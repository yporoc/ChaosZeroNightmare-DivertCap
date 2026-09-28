@echo off
rem SPDX-FileCopyrightText: 2026 netcatch contributors
rem SPDX-License-Identifier: GPL-3.0-only
rem ============================================================
rem  netcatch launcher   (ASCII only. do not add CJK in this file.)
rem
rem    setup         create .venv and install requirements.txt     (no admin)
rem    preflight     run the gates only, start nothing              (no admin)
rem    camake        sign a brand new CA for this repo              (no admin)
rem    cainstall     install OUR CA into the machine root store      (admin)
rem    catch LABEL   gates first, then capture (press ENTER to stop) (admin)
rem    mark LABEL    tag an action into the latest run               (no admin)
rem    status        list runs already captured                      (no admin)
rem    verify        re-run acceptance on the latest run             (no admin)
rem    snapshot      build the sanitized, shareable snapshot         (no admin)
rem    selftest      end-to-end rig test, needs the kernel driver    (admin)
rem    stop          kill leftovers + remove WinDivert service       (admin)
rem    cauninstall   remove OUR ca from BOTH stores when you're done (admin)
rem
rem  Everything writes inside this folder only. CA private key, captures and
rem  dictionaries are git-ignored. See README.md.
rem ============================================================
setlocal
cd /d "%~dp0"
set "T=%~dp0tools"
set "VENV=%~dp0.venv"
set "PY=%VENV%\Scripts\python.exe"

if /I "%~1"=="setup" goto setup

if not exist "%PY%" (
  echo [!] no virtualenv here: "%PY%"
  echo     do this first:  00_run.bat setup
  echo     now trying python from PATH - expect missing dependencies.
  set "PY=python"
)

if /I "%~1"=="preflight"  goto pf
if /I "%~1"=="camake"     goto camake
if /I "%~1"=="mark"       goto mark
if /I "%~1"=="status"     goto run_status
if /I "%~1"=="verify"     goto run_verify
if /I "%~1"=="snapshot"   goto run_snapshot
if /I "%~1"=="cainstall"  goto needadmin
if /I "%~1"=="cauninstall" goto needadmin
if /I "%~1"=="catch"      goto needadmin
if /I "%~1"=="selftest"   goto needadmin
if /I "%~1"=="stop"       goto needadmin
if "%~1"=="" goto menu
goto help

rem ---------------- admin-required commands ----------------
:needadmin
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [i] relaunching elevated ...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
  exit /b
)
if /I "%~1"=="cainstall"   goto cainstall
if /I "%~1"=="cauninstall" goto cauninstall
if /I "%~1"=="catch"       goto catch
if /I "%~1"=="selftest"    goto selftest
if /I "%~1"=="stop"        goto stop
goto help

:setup
echo [i] creating .venv ...
where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] no "python" on PATH. Install Python 3.9+ and tick "Add to PATH",
  echo         then run setup again.
  pause
  exit /b 1
)
python -m venv "%VENV%"
set "VPY=%VENV%\Scripts\python.exe"
if not exist "%VPY%" (
  echo [ERROR] venv was attempted but no interpreter exists at:
  echo         "%VPY%"
  echo         Most common cause: the antivirus deleted the freshly copied python.exe.
  echo         Whitelist this folder, delete .venv, run setup again.
  pause
  exit /b 1
)
echo [i] installing dependencies (this downloads from PyPI) ...
"%VPY%" -m pip install --disable-pip-version-check --timeout 120 --retries 5 -r "%~dp0requirements.txt"
if %errorlevel% neq 0 (
  echo [ERROR] pip install failed. Common causes: no network, a proxy blocking PyPI, or
echo         requirements.txt not being pure ASCII (pip decodes it with the system
echo         codepage, so CJK comments there blow up on zh-CN Windows). Fix and re-run.
  pause
  exit /b 1
)
"%VPY%" -c "import mitmproxy.version,zstandard;print('mitmproxy',mitmproxy.version.VERSION)"
set "PY=%VPY%"
echo.
echo [OK] venv ready. Next:  00_run.bat camake   then   00_run.bat cainstall
pause
exit /b 0

:camake
"%PY%" "%T%\ca_tool.py" make
if %errorlevel% neq 0 (
  echo [STOP] make failed. Most likely mitmproxy is not installed: run 00_run.bat setup
  pause
  exit /b 1
)
"%PY%" "%T%\ca_tool.py" throwaway
echo.
echo [i] now install it:  00_run.bat cainstall   (elevates, no prompt dialog)
pause
exit /b %errorlevel%

:cainstall
"%PY%" "%T%\ca_tool.py" install --where machine
set "RC=%errorlevel%"
if "%RC%"=="0" echo [i] verify the chain of trust:  python "%T%\tls_trust_probe.py"
pause
exit /b %RC%

:cauninstall
"%PY%" "%T%\ca_tool.py" uninstall --where all
pause
exit /b %errorlevel%

:catch
set "LB=%~2"
if "%LB%"=="" set "LB=all"
goto do_catch

:do_catch
"%PY%" "%T%\preflight.py"
if %errorlevel% neq 0 (
  echo.
  echo [STOP] preflight is RED. Each line says what to fix. Nothing was started.
  pause
  exit /b 1
)
echo.
echo [GO] gates passed. capturing as label: %LB%
ping -n 4 127.0.0.1 >nul
"%PY%" "%T%\catch.py" start --label %LB%
set "RC=%errorlevel%"
echo.
echo capture finished, exit=%RC%. data in %~dp0catchedsample
echo shareable output: run  00_run.bat snapshot   then send only the snapshot folder
pause
exit /b %RC%

:pf
"%PY%" "%T%\preflight.py"
echo.
echo preflight exit = %errorlevel%   (0 means you may capture; WARN does not block)
pause
exit /b %errorlevel%

:mark
set "LB2=%~2"
if "%LB2%"=="" (
  set /p LB2=label (what you just did, e.g. b1_t1_card):
)
if "%LB2%"=="" (
  echo empty label, abort.
  pause
  exit /b 2
)
"%PY%" "%T%\catch.py" mark %LB2% %3
exit /b %errorlevel%

:run_status
"%PY%" "%T%\catch.py" status
pause
exit /b 0

:run_verify
"%PY%" "%T%\catch.py" verify
echo verify exit = %errorlevel%
pause
exit /b %errorlevel%

:run_snapshot
"%PY%" "%T%\catch.py" snapshot
echo snapshot exit = %errorlevel%
pause
exit /b %errorlevel%

:selftest
"%PY%" "%T%\selftest_pipeline.py"
echo selftest exit = %errorlevel%
pause
exit /b %errorlevel%

:stop
taskkill /F /IM mitmdump.exe >nul 2>&1
taskkill /F /IM dumpcap.exe >nul 2>&1
sc stop WinDivert >nul 2>&1
sc delete WinDivert >nul 2>&1
echo --- residual capture processes (should print nothing) ---
tasklist /FI "IMAGENAME eq mitmdump.exe" | findstr /i mitmdump
tasklist /FI "IMAGENAME eq dumpcap.exe" | findstr /i dumpcap
echo --- WinDivert service (expect 1060 = not found) ---
sc query WinDivert | findstr /i STATE
pause
exit /b 0

:menu
echo.
echo  netcatch - what do you want to do?   (type number, ENTER)
echo    9) setup        create .venv and install dependencies  (do this first)
echo    1) preflight    run the gates only, start nothing
echo    2) catch        gates first, then capture  (asks for a LABEL)
echo    3) mark         tag an action into the latest run
echo    4) status       list runs already captured
echo    5) verify       re-run acceptance on the latest run
echo    6) snapshot     build the sanitized, shareable snapshot
echo    7) selftest     end-to-end rig test, does NOT touch any real target
echo    8) stop         kill leftovers + remove the kernel driver service
echo   10) camake       sign a brand new CA for this repo
echo   11) cainstall    install our CA (machine store, silent)
echo   12) cauninstall  remove our CA from both stores
echo    0) quit
echo.
set "CH="
set /p CH=select:
call :refreshpy
if "%CH%"=="9" goto setup
if "%CH%"=="1" goto pf
if "%CH%"=="2" goto menu_catch
if "%CH%"=="3" goto mark
if "%CH%"=="4" goto run_status
if "%CH%"=="5" goto run_verify
if "%CH%"=="6" goto run_snapshot
if "%CH%"=="7" call "%~f0" selftest & exit /b
if "%CH%"=="8" call "%~f0" stop & exit /b
if "%CH%"=="10" goto camake
if "%CH%"=="11" call "%~f0" cainstall & exit /b
if "%CH%"=="12" call "%~f0" cauninstall & exit /b
if "%CH%"=="0" exit /b 0
echo bad choice: %CH%
ping -n 2 127.0.0.1 >nul
goto menu

:menu_catch
set "LB="
set /p LB=label (empty ENTER = all):
if "%LB%"=="" set "LB=all"
call "%~f0" catch %LB%
exit /b

rem Re-point PY at the repo venv if it now exists. Without this, entering the menu
rem from a fresh clone (no .venv yet) leaves PY at the stopgap value "python", and
rem the venv check below then looks for a file literally named "python" and reports
rem "could not create a venv" even though creation succeeded. Measured 2026-09-28.
:refreshpy
if exist "%VENV%\Scripts\python.exe" set "PY=%VENV%\Scripts\python.exe"
exit /b 0

:help
echo 00_run.bat setup ^| preflight ^| camake ^| cainstall ^| catch LABEL ^| mark LABEL ^| status ^| verify ^| snapshot ^| selftest ^| stop ^| cauninstall
pause
exit /b 0
