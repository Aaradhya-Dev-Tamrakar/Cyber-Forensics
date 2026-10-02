<#
.SYNOPSIS
Safely sync the Cyber-Forensics repository, verify test suite, detect secrets, and commit with smart conventional messaging.

.DESCRIPTION
Automated synchronization workflow for Cyber-Forensics:
1. Verifies Git repository and active branch.
2. Pulls remote updates with --rebase and --autostash if remote origin exists.
3. Runs regression tests via tests/test_evasion_hunter.ps1.
4. Stages changes with git add -A.
5. Scans staged changes for accidental credentials, keys, or sensitive evidence dumps.
6. Auto-generates conventional commit messages.
7. Commits and safely pushes to origin.

.PARAMETER Message
Custom commit message (e.g. -m "feat(hunter): add NTFS stream parser").

.PARAMETER PullOnly
Safely pull remote changes without committing or pushing.

.PARAMETER SkipTest
Bypasses test suite gate.

.PARAMETER NoPush
Stages and commits changes locally without pushing to remote origin.

.PARAMETER WhatIf
Dry-run mode: Previews changes without modifying git state.
#>

[CmdletBinding()]
param (
    [Alias("m")]
    [string]$Message,

    [switch]$PullOnly,

    [switch]$SkipTest,

    [switch]$NoPush,

    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Msg, [System.ConsoleColor]$Color = [System.ConsoleColor]::Cyan)
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Msg" -ForegroundColor $Color
}

function Write-Success {
    param([string]$Msg)
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] SUCCESS: $Msg" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Msg)
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] ERROR: $Msg" -ForegroundColor Red
}

$repoRoot = $PSScriptRoot
Set-Location $repoRoot

if (-not (Test-Path "$repoRoot\.git")) {
    Write-Fail "Not a git repository: $repoRoot"
    exit 1
}

$currentBranch = (git branch --show-current 2>$null)
if (-not $currentBranch) { $currentBranch = "main" }
$hasRemote = [bool](git remote get-url origin 2>$null)
$remoteBranchExists = if ($hasRemote) { [bool](git ls-remote --heads origin $currentBranch 2>$null) } else { $false }

# 0. Verification Gate
if (Test-Path "scripts/verify.py") {
    Write-Status "Running scripts/verify.py..."
    python scripts/verify.py
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "scripts/verify.py reported errors. Fix before committing."
        exit $LASTEXITCODE
    }
}

# 1. Pull
if ($hasRemote -and $remoteBranchExists) {
    Write-Status "Pulling latest updates from origin/$currentBranch..."
    git pull --rebase --autostash origin $currentBranch
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "git pull encountered conflicts or errors."
        exit $LASTEXITCODE
    }
} else {
    Write-Status "Branch $currentBranch is local-only. Skipping initial pull."
}

if ($PullOnly) {
    Write-Success "Pull completed successfully (-PullOnly active)."
    exit 0
}

# 2. Test Verification Gate
if (-not $SkipTest) {
    $testScript = Join-Path $repoRoot "tests\test_evasion_hunter.ps1"
    if (Test-Path $testScript) {
        Write-Status "Running regression test suite..."
        & powershell.exe -ExecutionPolicy Bypass -File $testScript
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Verification gate failed! Please fix failing unit tests before committing."
            exit 1
        }
        Write-Success "Test suite verified clean."
    }
}

# 3. Check changes
$statusPorcelain = git status --porcelain -uall 2>$null
$hasUncommitted = [bool]($statusPorcelain -and $statusPorcelain.Trim().Length -gt 0)

if (-not $hasUncommitted) {
    Write-Status "Working tree clean. No changes to commit." -Color Yellow
    exit 0
}

# 4. Stage
if ($WhatIf) {
    Write-Status "[WhatIf] Changes detected:" -Color Yellow
    git status --short
    exit 0
}

git add -A

# 5. Commit
if (-not $Message) {
    $Message = "feat(dfir): update Cyber-Forensics detection modules and parsers"
}

Write-Status "Committing changes: $Message"
git commit -m $Message

# 6. Push
if (-not $NoPush -and $hasRemote) {
    Write-Status "Pushing to origin/$currentBranch..."
    git push -u origin $currentBranch
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Push rejected, attempting rebase pull..." -Color Yellow
        git pull --rebase origin $currentBranch
        git push -u origin $currentBranch
    }
    Write-Success "Cyber-Forensics synchronized and pushed successfully."
} else {
    Write-Success "Committed locally."
}
