@echo off
rem Live presenter: paste a GitHub link in the page and the Guardian does the rest.
cd /d "%~dp0"
.venv\Scripts\guardian serve %*
