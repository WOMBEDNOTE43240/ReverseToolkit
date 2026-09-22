@echo off
echo.
echo ========================================================
echo   Preparing Release Build
echo ========================================================
echo.

REM Clean previous builds
echo Cleaning previous builds...
if exist "ReverseToolkit\bin" rmdir /s /q "ReverseToolkit\bin"
if exist "ReverseToolkit\obj" rmdir /s /q "ReverseToolkit\obj"
if exist "Release" rmdir /s /q "Release"

echo.
echo Building Release configuration...
cd ReverseToolkit
dotnet publish -c Release -r win-x64 --self-contained false -o ..\Release

if errorlevel 1 (
    echo ERROR: Build failed!
    cd ..
    pause
    exit /b 1
)

cd ..

echo.
echo Creating release package...
mkdir "Release-Package" 2>nul

REM Copy files
xcopy /Y "Release\ReverseToolkit.exe" "Release-Package\"
xcopy /Y "Release\ReverseToolkit.dll" "Release-Package\"
xcopy /Y "Release\ReverseToolkit.runtimeconfig.json" "Release-Package\"
xcopy /Y "README.md" "Release-Package\"
xcopy /Y "QUICKSTART.md" "Release-Package\"
xcopy /Y "LICENSE" "Release-Package\"

echo.
echo ========================================================
echo   Release package ready in Release-Package folder!
echo ========================================================
echo.
echo Files included:
dir /b "Release-Package"
echo.
echo Now you can:
echo 1. Zip the Release-Package folder
echo 2. Upload to GitHub Releases
echo.
pause
