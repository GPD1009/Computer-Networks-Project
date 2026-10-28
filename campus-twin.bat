@echo off
REM Launch the Campus SDN Digital Twin from Windows (runs inside WSL Ubuntu as root).
REM   campus-twin.bat                 bring it up + interactive CLI
REM   campus-twin.bat --services      also start the campus servers
REM   campus-twin.bat --scenario normal
REM One-time setup first:  wsl -d Ubuntu -u root bash -lc "cd /mnt/... && sudo scripts/install.sh"
wsl.exe -d Ubuntu -u root campus-twin %*
