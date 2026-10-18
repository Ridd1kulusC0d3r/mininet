@echo off
REM Lancador de dois cliques (Windows) - mininet-sec-lab
REM Roda a suite pytest e os 6 cases em modo sim. Modo real (Mininet) so em Linux.
cd /d "%~dp0\.."
echo ============================================
echo   mininet-sec-lab - verificacao rapida
echo ============================================
python -m pip install -q pytest 2>nul
echo.
echo ^>^> Suite de deteccao (pytest):
python -m pytest tests/ -q
echo.
echo ^>^> Cases (modo sim):
python cases\runner.py
echo.
echo Evidencias seladas em: out\*.json
echo Abra docs\manual.html no navegador para o guia completo.
pause
