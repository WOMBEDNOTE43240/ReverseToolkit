@echo off
echo.
echo ========================================================
echo   Building Reverse Engineering Toolkit
echo ========================================================
echo.

echo Checking .NET SDK...
dotnet --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: .NET SDK not installed!
    echo Download from: https://dotnet.microsoft.com/download/dotnet/8.0
    pause
    exit /b 1
)

echo .NET SDK found!
echo.

echo Restoring NuGet packages...
cd ReverseToolkit
dotnet restore
if errorlevel 1 (
    echo ERROR: Package restore failed!
    pause
    exit /b 1
)

echo.
echo Building Release configuration...
dotnet build -c Release
if errorlevel 1 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================================
echo   BUILD COMPLETED SUCCESSFULLY!
echo ========================================================
echo.
echo Executable location:
echo   bin\Release\net8.0-windows\ReverseToolkit.exe
echo.
echo IMPORTANT: Run as administrator for full functionality!
echo.

cd ..
pause
