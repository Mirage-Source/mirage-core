# Generate the SSH host key the honeypot core presents to attackers.
# The core fatals if core\config\hostkey is missing. Run once before compose up.
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $PSScriptRoot
$key  = Join-Path $here "core\config\hostkey"
$dir  = Split-Path -Parent $key

if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
if (Test-Path $key) {
    Write-Host "host key already exists at $key -- leaving it untouched."
    exit 0
}

# Requires OpenSSH (ssh-keygen). Ed25519 in OpenSSH PEM format, no passphrase.
ssh-keygen -t ed25519 -f $key -N '""' -C "mirage-honeypot" -q
Write-Host "wrote $key (and $key.pub)"
