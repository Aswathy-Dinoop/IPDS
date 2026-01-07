@echo off
echo ===================================================
echo   Building Neural Shield IDPS Executable (.exe)
echo ===================================================

echo Step 1: Installing PyInstaller...
pip install pyinstaller

echo.
echo Step 2: Creating Build...
echo This process may take a few minutes because TensorFlow is very large.
echo.

pyinstaller --noconfirm --onedir --console --name "NeuralShield_IDPS" --add-data "templates;templates" --add-data "static;static" --add-data "model;model" --add-data "data;data" --hidden-import="sklearn" --hidden-import="pandas" --hidden-import="tensorflow" app.py

echo.
echo ===================================================
echo   BUILD COMPLETE!
echo ===================================================
echo.
echo Your executable is located in: dist\NeuralShield_IDPS\NeuralShield_IDPS.exe
echo.
echo IMPORTANT: You must run the .exe as Administrator for the sniffer to work.
echo.
pause
