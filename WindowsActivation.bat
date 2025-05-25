@echo off
color 4F
echo ====================================
echo      WINDOWS 11 ACTIVATION TOOL
echo ====================================
color 07
echo.
echo Welcome to WINDOWS 11 ACTIVATION!
echo.
echo.
setlocal EnableDelayedExpansion

:: --- Check for Admin Privileges ---
openfiles >nul 2>&1
if %errorlevel% NEQ 0 (
   echo [ERROR] Please run this script as Administrator!
   exit /b 1
   pause
)

:: --- Title & Information ---
title Windows 11 Activation (ALL VERSIONS)
cls
echo ======================================
echo      Activate Windows 11 for FREE!
echo ======================================
echo.
echo Supported Editions:
echo - Home
echo - Professional
echo - Education
echo - Enterprise
echo.
echo ======================================
echo.

:: --- Confirm User Wants to Proceed ---
choice /M "Do you wish to proceed with activation?"
if errorlevel 2 exit /b
pause

:: --- Clean Previous Keys & KMS Settings ---
echo [*] Cleaning previous activation data...
cscript //nologo slmgr.vbs /ckms >nul
cscript //nologo slmgr.vbs /upk >nul
cscript //nologo slmgr.vbs /cpky >nul

:: --- Detect Windows Edition ---
for /f "tokens=2 delims==" %%i in ('"wmic os get Caption /value | findstr Caption"') do set "WIN_EDITION=%%i"
set "WIN_EDITION=%WIN_EDITION:~0,50%"
echo [*] Detected Edition: %WIN_EDITION%

set "KEY="
set "EDITION_FOUND=0"

:: --- Assign Product Key Based on Edition ---
echo [*] Selecting product key...
echo %WIN_EDITION% | find /I "Enterprise" >nul && (
   set "KEY=NPPR9-FWDCX-D2C8J-H872K-2YT43"
   set "EDITION_FOUND=1"
)

echo %WIN_EDITION% | find /I "Home" >nul && (
   set "KEY=TX9XD-98N7V-6WMQ6-BX7FG-H8Q99"
   set "EDITION_FOUND=1"
)

echo %WIN_EDITION% | find /I "Education" >nul && (
   set "KEY=NW6C2-QMPVW-D7KKK-3GKT6-VCFB2"
   set "EDITION_FOUND=1"
)

echo %WIN_EDITION% | find /I "Pro" >nul && (
   set "KEY=W269N-WFGWX-YVC9B-4J6C9-T83GX"
   set "EDITION_FOUND=1"
)

if "%EDITION_FOUND%"=="0" (
   echo [ERROR] Unsupported Windows Edition: %WIN_EDITION%
   goto end
)

:: --- Install Product Key ---
echo [*] Installing product key: %KEY%
cscript //nologo slmgr.vbs /ipk %KEY%
if %errorlevel% NEQ 0 (
   echo [ERROR] Failed to install product key.
   goto end
)

:: --- Try KMS Servers in Order ---
set KMSLIST=kms7.msguides.com kms8.msguides.com kms9.msguides.com
set ACTIVATED=0

for %%K in (%KMSLIST%) do (
   echo [*] Setting KMS Server: %%K
   cscript //nologo slmgr.vbs /skms %%K:1688 >nul
   echo [*] Attempting activation...
   for /f "tokens=*" %%A in ('cscript //nologo slmgr.vbs /ato 2^>^&1') do (
      echo %%A | find /I "successfully" >nul && (
         set ACTIVATED=1
         echo [SUCCESS] Windows Has Been Successfully Activated!
         goto activated
      )
   )
   echo [!] Activation failed with server %%K. Trying next...
)

:activated
if "%ACTIVATED%"=="1" (
   echo.
   echo ======================================
   echo [*] WINDOWS ACTIVATION COMPLETED! 
   echo ======================================
   goto end
) else (
   echo [ERROR] ALL KMS servers failed. Please check your internet connection or try again later.
   goto end
)

:end
exit /b
pause >nul
