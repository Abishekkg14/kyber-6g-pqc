@echo off
title Kyber-6G Ground Station
echo.
echo   KYBER-6G GROUND STATION
echo   - starts the UAV service on the Raspberry Pi (if reachable)
echo   - starts the secure ground station in WSL (and again by itself if it ever crashes)
echo   - opens the dashboard at http://127.0.0.1:8600 when it is ready
echo   Close this window to stop the ground station.
echo.
wsl -d Ubuntu-22.04 -u root -- bash "/home/abishek14/Kyber-6G project latest/Kyber-6G project/Kyber-6G project/run/kyber6g.sh" run --open
echo.
echo Ground station stopped.
pause
