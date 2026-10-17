# Generate the SSH host keys the honeypot core presents to attackers.
# Mirrors generate_hostkey.sh: config\hostkey (ed25519) is required, the RSA
# and ECDSA keys are optional but a stock Ubuntu sshd offers all three.
# Safe to re-run: existing keys are kept. Requires OpenSSH (ssh-keygen).
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $PSScriptRoot
$base = Join-Path $here "config\hostkey"
$dir  = Split-Path -Parent $base
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

function New-HostKey([string]$path, [string[]]$keygenArgs) {
    if (Test-Path $path -PathType Leaf) {
        Write-Host "host key already exists at $path -- leaving it untouched."
        return
    }
    # Left behind by a compose bind mount of a file that did not exist yet.
    if (Test-Path $path -PathType Container) { Remove-Item $path }
    ssh-keygen @keygenArgs -f $path -N '""' -C '""' -q
    Write-Host "wrote $path (and $path.pub)"
}

New-HostKey $base @("-t", "ed25519")
New-HostKey "${base}_rsa" @("-t", "rsa", "-b", "3072")
New-HostKey "${base}_ecdsa" @("-t", "ecdsa", "-b", "256")
