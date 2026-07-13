$ErrorActionPreference = "Stop"
python "$PSScriptRoot\validate.py"
exit $LASTEXITCODE
