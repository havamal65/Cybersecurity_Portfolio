@echo off
echo ====================================================================
echo ESP32 Security Simulation - Virtual Environment Recreation
echo ====================================================================

echo.
echo This script will:
echo 1. Deactivate the current virtual environment
echo 2. Rename the existing venv folder to venv_old
echo 3. Create a fresh virtual environment
echo 4. Install all required packages
echo 5. Activate the new environment
echo.

set VENV_DIR=venv
set OLD_VENV_DIR=venv_old

REM Deactivate current virtual environment if active
if defined VIRTUAL_ENV (
    echo Deactivating current virtual environment...
    call deactivate
)

REM Rename existing venv if it exists
if exist %VENV_DIR% (
    echo Renaming existing virtual environment...
    if exist %OLD_VENV_DIR% (
        rmdir /s /q %OLD_VENV_DIR%
    )
    rename %VENV_DIR% %OLD_VENV_DIR%
)

REM Create fresh virtual environment
echo.
echo Creating a fresh virtual environment...
python -m venv %VENV_DIR%

REM Activate the new environment
echo.
echo Activating new virtual environment...
call %VENV_DIR%\Scripts\activate.bat

REM Upgrade pip and setuptools
echo.
echo Upgrading pip and setuptools...
python -m pip install --upgrade pip setuptools wheel

REM Install dependencies in the correct order
echo.
echo Installing dependencies...
python -m pip install werkzeug==2.0.1
python -m pip install flask==2.0.1
python -m pip install cryptography
python -m pip install pycryptodome>=3.10.1
python -m pip install scapy==2.4.5
python -m pip install requests>=2.26.0
python -m pip install flask-wtf>=1.0.0
python -m pip install flask-sqlalchemy>=2.5.1
python -m pip install netifaces>=0.11.0
python -m pip install pytest==6.2.5
python -m pip install coverage==6.1.2

REM Verify installation
echo.
echo Verifying installations...
python -c "import flask; print(f'Flask version: {flask.__version__} at {flask.__file__}')"
python -c "import werkzeug; print(f'Werkzeug version: {werkzeug.__version__} at {werkzeug.__file__}')"
python -c "import cryptography; print(f'Cryptography version: {cryptography.__version__} at {cryptography.__file__}')"

echo.
echo ====================================================================
echo Virtual environment recreation completed!
echo The new environment is now activated.
echo.
echo You can now run your application with: python main.py
echo ====================================================================
