@echo off
rem ZHack - escaner de seguridad web (solo webs propias o autorizadas)
cd /d "%~dp0"
python -m zhack %*
