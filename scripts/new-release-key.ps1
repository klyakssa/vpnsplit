# Creates the key that signs releases - ONCE. Programs installed on other
# people's machines accept updates only when they are signed with this key.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\new-release-key.ps1
#
# The private half goes to %USERPROFILE%\.vpnsplit\release-key.pem and must
# never be put into the repository or sent to anyone. Keep a copy of it in a
# safe place:
#   - lose it  -> installed copies can never be updated again (a new key
#                 means everybody has to install by hand once more);
#   - leak it  -> whoever has it AND your GitHub account can run their code
#                 as SYSTEM on every machine that has vpnsplit.
# The public half (a number, not a secret) is written into the service source:
# crates\vpnsplit-svc\src\update_key.rs.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$dir = Join-Path $env:USERPROFILE '.vpnsplit'
$key = Join-Path $dir 'release-key.pem'
if (Test-Path $key) { throw "the key already exists: $key - it is not replaced. Delete it yourself only if you know what that costs." }
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { throw 'openssl is not found (it comes with Git for Windows)' }

New-Item -ItemType Directory -Force $dir | Out-Null
cmd /c "openssl genrsa -out `"$key`" 3072 2>nul"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $key)) { throw 'openssl did not create the key' }
# The key inherits the rights of the profile folder: the owner, the system
# and administrators.

[string]$modulus = (cmd /c "openssl rsa -in `"$key`" -noout -modulus 2>nul") -replace '^Modulus=', ''
if ($modulus.Length -ne 768 -or $modulus -notmatch '^[0-9A-Fa-f]+$') { throw 'could not read the public half of the key' }

$source = Join-Path $root 'crates\vpnsplit-svc\src\update_key.rs'
$utf8 = New-Object Text.UTF8Encoding $false
$text = [IO.File]::ReadAllText($source, $utf8)
$text = [regex]::Replace($text, 'pub const MODULUS: &str = "[0-9A-Fa-f]*";', "pub const MODULUS: &str = `"$modulus`";")
[IO.File]::WriteAllText($source, $text, $utf8)
Write-Host "private key: $key  (keep a copy somewhere safe, never publish)"
Write-Host "public half written to: $source"
