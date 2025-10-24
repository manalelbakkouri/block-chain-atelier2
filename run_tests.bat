@echo off
setlocal

echo ===========================================
echo  Lancement des tests automatisés
echo ===========================================


set "MINGW_BIN=C:\msys64\mingw64\bin"


set "PATH=%MINGW_BIN%;%PATH%"


if not exist "%MINGW_BIN%\g++.exe" (
    echo  ERREUR : g++ introuvable dans %MINGW_BIN%
    echo Installez MSYS2 ou mettez à jour le chemin.
    pause
    exit /b 1
)


if not exist "atelier2.cpp" (
    echo  ERREUR : atelier2.cpp non trouvé dans ce dossier !
    echo Dossier actuel : %CD%
    dir /b
    pause
    exit /b 1
)

echo Compilation en cours...
g++ -std=c++17 -O2 atelier2.cpp -o blockchain_ac_test.exe

if errorlevel 1 (
    echo.
    echo  ECHEC DE LA COMPILATION.
    echo Les messages d'erreur de g++ sont affiches ci-dessus.
    pause
    exit /b 1
)

echo.
echo  Compilation reussie. Execution des tests...
blockchain_ac_test.exe

echo.
echo ===========================================
echo  Tous les tests sont termines.
echo ===========================================
pause