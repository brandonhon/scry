# scripts\build.ps1
#
# Build/test helper for scry on Windows. Mirrors the Makefile targets.
#
# Usage:
#   .\scripts\build.ps1 build
#   .\scripts\build.ps1 test
#   .\scripts\build.ps1 cross
#
# Requires: Go 1.22+, git, PowerShell 5.1+ (or PowerShell 7).

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('build', 'install', 'test', 'test-race', 'cover', 'fmt', 'vet', 'tidy', 'ci', 'cross', 'clean', 'run', 'help')]
    [string]$Target = 'build',

    [string]$Bin = 'scry',
    [string]$Pkg = './cmd/scry',
    [string]$OutDir = 'bin',
    [int]$Port = 22
)

$ErrorActionPreference = 'Stop'
$env:GO111MODULE = 'on'

function Get-Version {
    try {
        $v = git describe --tags --always --dirty 2>$null
        if ($LASTEXITCODE -eq 0 -and $v) { return $v.Trim() }
    } catch {}
    return 'dev'
}

$Version = Get-Version
$LdFlags = "-s -w -X github.com/bhoneycutt/scry/internal/cli.Version=$Version"

function Ensure-OutDir {
    if (-not (Test-Path $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir | Out-Null
    }
}

function Invoke-Go {
    param([string[]]$Args)
    & go @Args
    if ($LASTEXITCODE -ne 0) {
        throw "go $($Args -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Cmd-Build {
    Ensure-OutDir
    $outFile = Join-Path $OutDir "$Bin.exe"
    Invoke-Go @('build', '-ldflags', $LdFlags, '-o', $outFile, $Pkg)
    Write-Host "Built $outFile ($Version)"
}

function Cmd-Install {
    Invoke-Go @('install', '-ldflags', $LdFlags, $Pkg)
}

function Cmd-Test      { Invoke-Go @('test', './...') }
function Cmd-Test-Race { Invoke-Go @('test', '-race', './...') }

function Cmd-Cover {
    Invoke-Go @('test', '-coverprofile=coverage.out', './...')
    Invoke-Go @('tool', 'cover', '-func=coverage.out')
}

function Cmd-Fmt  { Invoke-Go @('fmt', './...') }
function Cmd-Vet  { Invoke-Go @('vet', './...') }
function Cmd-Tidy { Invoke-Go @('mod', 'tidy') }

function Cmd-CI {
    Cmd-Vet
    Cmd-Test
}

function Cmd-Cross {
    Ensure-OutDir
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    Invoke-Go @('build', '-ldflags', $LdFlags, '-o', (Join-Path $OutDir "$Bin-linux-amd64"), $Pkg)

    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    Invoke-Go @('build', '-ldflags', $LdFlags, '-o', (Join-Path $OutDir "$Bin-windows-amd64.exe"), $Pkg)

    Remove-Item Env:GOOS
    Remove-Item Env:GOARCH
}

function Cmd-Clean {
    if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
    foreach ($p in @('coverage.out', 'coverage.html')) {
        if (Test-Path $p) { Remove-Item -Force $p }
    }
}

function Cmd-Run {
    Cmd-Build
    & (Join-Path $OutDir "$Bin.exe") '127.0.0.1' '-p' "$Port"
}

function Cmd-Help {
    @"
Usage: .\scripts\build.ps1 <target> [-Port N]

Targets:
  build       Build the scry binary for Windows
  install     go install into %GOBIN%
  test        Run unit tests
  test-race   Run unit tests with the race detector
  cover       Run tests with coverage
  fmt         gofmt all Go sources
  vet         Run go vet
  tidy        Run go mod tidy
  ci          Vet + test (matches CI)
  cross       Cross-compile linux/amd64 + windows/amd64 binaries
  clean       Remove build artifacts
  run         Build and run against 127.0.0.1:<Port> (default 22)
  help        Show this message
"@ | Write-Host
}

switch ($Target) {
    'build'     { Cmd-Build }
    'install'   { Cmd-Install }
    'test'      { Cmd-Test }
    'test-race' { Cmd-Test-Race }
    'cover'     { Cmd-Cover }
    'fmt'       { Cmd-Fmt }
    'vet'       { Cmd-Vet }
    'tidy'      { Cmd-Tidy }
    'ci'        { Cmd-CI }
    'cross'     { Cmd-Cross }
    'clean'     { Cmd-Clean }
    'run'       { Cmd-Run }
    'help'      { Cmd-Help }
}
