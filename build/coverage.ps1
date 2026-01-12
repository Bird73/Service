[CmdletBinding()]
param(
    [switch]$NoBuild,
    [switch]$NoRestore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$artifactsRoot = Join-Path $repoRoot 'artifacts'
$resultsDir = Join-Path $artifactsRoot 'test-results'
$coverageDir = Join-Path $artifactsRoot 'coverage'
$runSettings = Join-Path $PSScriptRoot 'coverage.runsettings'

New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null
New-Item -ItemType Directory -Force -Path $coverageDir | Out-Null

Write-Host "Repo: $repoRoot"
Write-Host "Results: $resultsDir"
Write-Host "Coverage: $coverageDir"

Push-Location $repoRoot
try {
    if (-not $NoRestore) {
        dotnet restore
    }

    dotnet tool restore

    $testArgs = @(
        'test',
        '.\\Security.sln',
        '-c', 'Release',
        '--collect', 'XPlat Code Coverage',
        '--settings', $runSettings,
        '--results-directory', $resultsDir
    )

    if ($NoBuild) {
        $testArgs += '--no-build'
    }

    Write-Host "Running: dotnet $($testArgs -join ' ')"
    & dotnet @testArgs

    if ($LASTEXITCODE -ne 0)
    {
        throw "dotnet test failed with exit code $LASTEXITCODE"
    }

    $reportsGlob = "$resultsDir/**/coverage.cobertura.xml"

    Write-Host "Generating report from: $reportsGlob"
    dotnet tool run reportgenerator `
        "-reports:$reportsGlob" `
        "-targetdir:$coverageDir" `
        "-reporttypes:Html;HtmlSummary;TextSummary"

    Write-Host "Coverage report: $coverageDir\\index.html"
    Write-Host "Coverage summary: $coverageDir\\Summary.txt"
}
finally {
    Pop-Location
}
