@echo off
title CTF工具箱
cd /d "%~dp0"

echo ========================================
echo   CTF工具箱
echo ========================================
echo.

set PYTHON_CMD=

py --version >nul 2>nul
if not errorlevel 1 (
    set PYTHON_CMD=py
    goto found
)

python --version >nul 2>nul
if not errorlevel 1 (
    set PYTHON_CMD=python
    goto found
)

if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python314\python.exe" (
    set "PYTHON_CMD=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python314\python.exe"
    goto found
)

if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe" (
    set "PYTHON_CMD=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe"
    goto found
)

if exist "C:\Python314\python.exe" (
    set "PYTHON_CMD=C:\Python314\python.exe"
    goto found
)

if exist "C:\Python312\python.exe" (
    set "PYTHON_CMD=C:\Python312\python.exe"
    goto found
)

echo ERROR: Python not found!
echo Please install Python 3.8+ from https://www.python.org
goto end

:found
echo Python: %PYTHON_CMD%
%PYTHON_CMD% --version
echo.

echo Checking dependencies...
%PYTHON_CMD% -c "import flask" >nul 2>nul
if errorlevel 1 (
    echo Installing Flask...
    %PYTHON_CMD% -m pip install flask
)

%PYTHON_CMD% -c "from PIL import Image" >nul 2>nul
if errorlevel 1 (
    echo Installing Pillow...
    %PYTHON_CMD% -m pip install Pillow
)

%PYTHON_CMD% -c "import openpyxl" >nul 2>nul
if errorlevel 1 (
    echo Installing openpyxl...
    %PYTHON_CMD% -m pip install openpyxl
)

%PYTHON_CMD% -c "import pandas" >nul 2>nul
if errorlevel 1 (
    echo Installing pandas...
    %PYTHON_CMD% -m pip install pandas
)

echo.
echo ========================================
echo   Server: http://127.0.0.1:5000
echo   Press Ctrl+C to stop
echo ========================================
echo.

start "" cmd /c "timeout /t 3 /nobreak >nul & start http://127.0.0.1:5000"
%PYTHON_CMD% app.py

:end
echo.
pause
