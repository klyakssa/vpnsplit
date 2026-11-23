# Makes a release: the installer, its description and the signature of the
# description - the three files that go into a GitHub release.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\make-release.ps1
#
# Installed copies look at
#   https://github.com/klyakssa/vpnsplit/releases/latest/download/<file>
# every six hours, check the signature with the public key baked into them,
# and install the release if its build number is greater than their own.
# So: upload ALL THREE files from dist\ to a new release, with exactly these
# names, and do not mark the release as a pre-release.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$key = Join-Path $env:USERPROFILE '.vpnsplit\release-key.pem'
if (-not (Test-Path $key)) { throw "no release key: $key - create it once with scripts\new-release-key.ps1" }

# The build number is the time of the build; a later release is a greater number.
$build = Get-Date -Format 'yyyyMMddHHmm'
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'make-setup.ps1') -build $build
if ($LASTEXITCODE -ne 0) { throw 'the installer was not built' }

$dist = Join-Path $root 'dist'
$setup = Join-Path $dist 'vpnsplit-setup.exe'
$manifest = Join-Path $dist 'vpnsplit-setup.manifest'
$signature = Join-Path $dist 'vpnsplit-setup.manifest.sig'
$version = (Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
$size = (Get-Item $setup).Length
$text = "vpnsplit-update 1`nbuild=$build`nversion=$version`nsize=$size`nsha256=$hash`n"
[IO.File]::WriteAllText($manifest, $text, (New-Object Text.UTF8Encoding $false))

& openssl dgst -sha256 -sign $key -out $signature $manifest
if ($LASTEXITCODE -ne 0) { throw 'openssl did not sign the description' }

# The same check the installed service will make, by the same code.
& (Join-Path $root 'target\release\vpnsplit-svc.exe') update verify $manifest $signature
if ($LASTEXITCODE -ne 0) { throw 'the service does NOT accept this signature - do not publish' }

Write-Host ''
Write-Host "release $version, build $build - upload these three files to a new GitHub release:"
Get-ChildItem $setup, $manifest, $signature | ForEach-Object { Write-Host "  $($_.FullName)  ($($_.Length) bytes)" }
Write-Host "suggested tag: v$version-$build"
