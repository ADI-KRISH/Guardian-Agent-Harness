@echo off
cd /d %~dp0
.venv\Scripts\streamlit.exe run ui\app.py --server.headless true --browser.gatherUsageStats false

