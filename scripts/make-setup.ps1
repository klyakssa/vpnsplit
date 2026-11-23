# Builds dist\vpnsplit-setup.exe: one file that installs, updates and
# removes vpnsplit. No administrator rights are needed to BUILD it; the
# installer asks for them itself when it is run.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\make-setup.ps1
#
# Steps: release build of everything that is installed -> collect it into
# target\payload -> release build of the installer with that folder baked in.
#
# -build is the build number baked into the programs (digits only). Zero, the
# default, means "development build": such a build never updates itself.
# Releases are made by scripts\make-release.ps1, which passes a real number.
param([string]$build = '0')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

function Step([string]$what) { Write-Host "== $what" }

$built = Get-Date -Format 'dd.MM.yyyy HH:mm'
$env:VPNSPLIT_BUILD = $build
try {
    Step "release build: service, window, launcher, hook (build number $build)"
    cargo build --release -p vpnsplit-svc -p vpnsplit-ui -p vpnsplit-launch -p vpnsplit-hook
    if ($LASTEXITCODE -ne 0) { throw 'release build failed' }

    Step 'collecting payload'
    $payload = Join-Path $root 'target\payload'
    if (Test-Path $payload) { Remove-Item -Recurse -Force $payload }
    New-Item -ItemType Directory -Force $payload | Out-Null
    $files = @(
        'target\release\vpnsplit-svc.exe',
        'target\release\vpnsplit-ui.exe',
        'target\release\vpnsplit-launch.exe',
        'target\release\vpnsplit_hook.dll',
        'vendor\windivert\WinDivert.dll',
        'vendor\windivert\WinDivert64.sys'
    )
    foreach ($file in $files) {
        $from = Join-Path $root $file
        if (-not (Test-Path $from)) { throw "missing: $file" }
        Copy-Item $from $payload
    }

    Step 'release build: installer'
    $env:VPNSPLIT_PAYLOAD = $payload
    $env:VPNSPLIT_BUILT = $built
    cargo build --release -p vpnsplit-setup
    if ($LASTEXITCODE -ne 0) { throw 'installer build failed' }
}
finally {
    Remove-Item Env:\VPNSPLIT_BUILD, Env:\VPNSPLIT_PAYLOAD, Env:\VPNSPLIT_BUILT -ErrorAction SilentlyContinue
}

$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$out = Join-Path $dist 'vpnsplit-setup.exe'
Copy-Item (Join-Path $root 'target\release\vpnsplit-setup.exe') $out -Force
$size = [math]::Round((Get-Item $out).Length / 1MB, 1)
Step "done: $out ($size MB, built $built, build number $build)"
