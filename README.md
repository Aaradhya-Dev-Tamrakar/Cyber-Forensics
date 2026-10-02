# Cyber-Forensics 🔬🛡️

A lightweight, deterministic Windows Digital Forensics & Incident Response (DFIR) triage and stealth evasion hunting engine.

---

## ⚡ Key Capabilities

1. **🕵️ Multi-Layer Evasion Hunter (`EvasionHunter.ps1`)**:
   - **Super-Hidden Detection**: Discovers files marked with both `Hidden` and `System` attributes.
   - **NTFS Alternate Data Streams (ADS)**: Uncovers secondary payload streams (`file.txt:hidden.exe`).
   - **CLSID Namespace Spoofing**: Detects folders masquerading with `{GUID}` shell extensions.
   - **Unicode & RLO Obfuscation**: Identifies Right-To-Left Override (`\u202E`) and zero-width characters in paths.
   - **Win32 Namespace Exploitation**: Flags reserved names (`CON`, `NUL`) and trailing dot/space bypasses.
   - **File Header (Magic Byte) Discrepancies**: Checks first bytes (e.g. `MZ` `0x4D 0x5A`) to detect executables disguised as images or text.

2. **📜 Execution Artifact Harvester (`ArtifactHarvester.ps1`)**:
   - Parses Windows **Prefetch (`.pf`)** files to reconstruct exact execution timelines.
   - Harvests process execution history and generates cryptographic evidence summaries.

3. **🔒 Cryptographic Chain of Custody**:
   - Generates deterministic SHA-256 ledgers with UTC timestamps for forensic evidence integrity.

---

## 🚀 Usage

### 1. Run Evasion Scan
```powershell
# Scan current directory or target drive
.\src\EvasionHunter.ps1 -TargetPath "C:\TargetDirectory"

# Output structured JSON for SIEM / EDR ingestion
.\src\EvasionHunter.ps1 -TargetPath "C:\TargetDirectory" -JsonOutput
```

### 2. Harvest Windows Execution Artifacts
```powershell
# Triage recent Prefetch execution history
.\src\ArtifactHarvester.ps1 -Limit 50
```

### 3. Run Verification Tests
```powershell
.\tests\test_evasion_hunter.ps1
```
