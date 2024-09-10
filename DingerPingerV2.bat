@echo off
setlocal enabledelayedexpansion

REM Check if the file iplist.txt exists
if not exist iplist.txt (
    echo IP list file not found.
    exit /b
)

REM Create an empty file named successful
echo. > successful.txt
echo. > error.txt

REM Read each line (IP address) from iplist.txt
for /f "tokens=*" %%A in (iplist.txt) do (
    set ip=%%A
    echo Pinging !ip!
    
    REM Run ping command and check if it was successful
    ping !ip! -n 1 | find "TTL" > nul
    if errorlevel 1 (
        echo !ip! did not reply
	echo !ip! >> error.txt
    ) else (
        echo !ip! replied
        echo !ip! >> successful.txt
    )
    echo.
)
echo Step 1 complete.

set "inputFile=successful.txt"
set "outputFile=processed.csv"

echo "Converting %inputFile% to %outputFile%..."

(
    echo Returned
    for /f "usebackq tokens=*" %%A in ("%inputFile%") do (
        set "line=%%A"
        REM Replace space with comma to convert to CSV
        set "line=!line: =,!"
        echo !line!
    )
) > "%outputFile%"

echo "Conversion completed. Output saved to %outputFile%."
echo Stage 2 complete.

set "inputFile=error.txt"
set "outputFile=processederror.csv"

echo "Converting %inputFile% to %outputFile%..."

(
    echo Error
    for /f "usebackq tokens=*" %%A in ("%inputFile%") do (
        set "line=%%A"
        REM Replace space with comma to convert to CSV
        set "line=!line: =,!"
        echo !line!
    )
) > "%outputFile%"

echo "Conversion completed. Output saved to %outputFile%."
pause
