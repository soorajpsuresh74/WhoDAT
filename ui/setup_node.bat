@echo off
setlocal enabledelayedexpansion

:: Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo Node.js is not installed. Please install Node.js and try again.
    exit /b
)
echo Node.js is installed.

:: Check if nodemon is installed globally
where nodemon >nul 2>nul
if %errorlevel% neq 0 (
    echo nodemon is not installed globally. Installing it now...
    npm install -g nodemon >nul 2>nul
    where nodemon >nul 2>nul
    if %errorlevel% neq 0 (
        echo Failed to install nodemon. Try running 'npm install -g nodemon' manually.
        exit /b
    )
)
echo nodemon is installed.

:: Install Node.js dependencies
if exist node_modules (
    echo node_modules already exists. Skipping npm install.
) else (
    echo Installing dependencies...
    npm install
    if %errorlevel% neq 0 (
        echo npm install failed.
        exit /b
    )
)

echo Node.js setup complete.

:: Run the UI application with nodemon
echo Starting UI application with nodemon...
nodemon server.js

if %errorlevel% neq 0 (
    echo Failed to start the UI application.
    exit /b
)

exit /b
