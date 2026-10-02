<#
.SYNOPSIS
Unit tests for Cyber-Forensics EvasionHunter.
#>

$testDir = Join-Path $PSScriptRoot "temp_specimen_suite"
if (Test-Path $testDir) { Remove-Item -LiteralPath $testDir -Recurse -Force }
New-Item -ItemType Directory -Path $testDir -Force | Out-Null

try {
    Write-Host "Setting up synthetic evasion test specimens..." -ForegroundColor Cyan

    # 1. Specimen: Super-Hidden File
    $superHidden = Join-Path $testDir "super_hidden.txt"
    Set-Content -LiteralPath $superHidden "Hidden payload"
    $item = Get-Item -LiteralPath $superHidden -Force
    $item.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System

    # 2. Specimen: PE Masquerade (MZ executable header named as .png)
    $masquerade = Join-Path $testDir "fake_image.png"
    [System.IO.File]::WriteAllBytes($masquerade, [byte[]]@(0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00))

    # 3. Specimen: CLSID Suffix Folder
    $clsidFolder = Join-Path $testDir "StealthFolder.{21EC2020-3AEA-1069-A2DD-08002B30309D}"
    New-Item -ItemType Directory -Path $clsidFolder -Force | Out-Null

    # Run Scanner
    $scannerScript = Join-Path $PSScriptRoot "..\src\EvasionHunter.ps1"
    $findings = & $scannerScript -TargetPath $testDir

    Write-Host "`nValidating detections..." -ForegroundColor Cyan
    $detectedTypes = $findings | ForEach-Object { $_.Indicators }

    $hasSuperHidden = $detectedTypes -match "SUPER_HIDDEN"
    $hasPE = $detectedTypes -match "PE_MASQUERADE"
    $hasCLSID = $detectedTypes -match "CLSID_SPOOF"

    if ($hasSuperHidden -and $hasPE -and $hasCLSID) {
        Write-Host "`n[PASS] All 3 synthetic evasion specimens were accurately detected with 100% recall!" -ForegroundColor Green
    } else {
        Write-Error "[FAIL] Scanner missed one or more evasion specimens."
        exit 1
    }
} finally {
    # Cleanup specimens
    if (Test-Path $testDir) {
        # Clear attributes to ensure clean removal
        Get-ChildItem -LiteralPath $testDir -Force -Recurse | ForEach-Object {
            $_.Attributes = [System.IO.FileAttributes]::Normal
        }
        Remove-Item -LiteralPath $testDir -Recurse -Force
    }
}
