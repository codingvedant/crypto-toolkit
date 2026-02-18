# Run the Crypto Toolkit demo
# Creates venv if needed and installs dependencies
$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv venv
}

& "./venv/Scripts/Activate.ps1"
pip install -r requirements.txt -q
pip install -e . -q
python examples/demo.py
