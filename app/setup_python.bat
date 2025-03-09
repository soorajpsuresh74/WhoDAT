@echo off
setlocal enabledelayedexpansion

:: Change to the "app" directory
cd /d %~dp0\app

:: Check if Python is installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Python is not installed. Please install Python and try again.
    exit /b
)
echo Python is installed.

:: Check if virtual environment exists
if exist venv (
    echo Virtual environment already exists. Skipping creation.
) else (
    echo Creating virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo Failed to create virtual environment.
        exit /b
    )
)

:: Activate virtual environment
call venv\Scripts\activate
echo Virtual environment activated.

:: Install Python dependencies
if exist requirements.txt (
    echo Installing dependencies from requirements.txt...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo Failed to install dependencies.
        exit /b
    )
) else (
    echo requirements.txt not found. Skipping...
)

echo Python setup complete.

:: Run main.py
if exist main.py (
    echo Running main.py...
    python main.py
    if %errorlevel% neq 0 (
        echo Failed to execute main.py.
        exit /b
    )
) else (
    echo main.py not found. Skipping execution.
)

exit /b
