@echo off
echo ===================================================
echo ESP32 Security Simulation - Setup and Run
echo ===================================================

echo.
echo Creating and activating virtual environment...
if not exist venv (
    python -m venv venv
) else (
    echo Virtual environment already exists
)

call venv\Scripts\activate

echo.
echo Upgrading pip...
python -m pip install --upgrade pip

echo.
echo Installing dependencies...
if exist requirements_flexible.txt (
    pip install -r requirements_flexible.txt
) else (
    pip install -r requirements.txt
)

echo.
echo Updating simulator file with adapter compatibility...
if exist network\simulator.py.new (
    move /Y network\simulator.py network\simulator.py.bak
    move /Y network\simulator.py.new network\simulator.py
    echo Simulator file updated
) else (
    echo No simulator update file found
)

echo.
echo ===================================================
echo Setup complete! Running the application...
echo ===================================================
echo.

python main.py

pause
