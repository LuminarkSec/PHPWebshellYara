# Portable PHP web-shell hunting with YARA 

This PowerShell script downloads a checksum-verified **official YARA v4.5.5 Windows x64 binary**, caches focused YARA rules from five GitHub repositories, validates/compiles each entry-point rule file separately, recursively scans any target directory, and creates per-file and per-rule-match reports. It does **not** execute, change or quarantine PHP samples. Administrator permissions are not required for the default per-user installation.

## Quick start

Open **Windows PowerShell** in the directory containing `Invoke-PHPWebshellScan.ps1` and run:

```powershell
# Install YARA, acquire/cache YARA rules, and scan recursively
.\Invoke-PHPWebshellScan.ps1 -ScanPath 'D:\Samples\PHP-Shells'

# Refresh GitHub rule snapshots, without scanning
.\Invoke-PHPWebshellScan.ps1 -UpdateRules

# Run later, without network requests (the first run must have succeeded)
.\Invoke-PHPWebshellScan.ps1 -ScanPath 'D:\Samples\PHP-Shells' -Offline

# Custom output path and SHA-256 for all eligible files
.\Invoke-PHPWebshellScan.ps1 -ScanPath 'D:\Samples\PHP-Shells' `
  -OutputDir 'D:\Analysis\YaraOutput' -HashAll

# Remove the default 25 MiB per-file scan limit: scan ALL file sizes
.\Invoke-PHPWebshellScan.ps1 -ScanPath 'D:\Samples\PHP-Shells' -MaxFileSizeMB 0

# Use a newer YARA distribution already obtained and verified yourself
.\Invoke-PHPWebshellScan.ps1 -ScanPath 'D:\Samples\PHP-Shells' `
  -YaraExe 'C:\Tools\YARA\yara64.exe'
```

If execution policy prevents running the downloaded script, inspect it first and use `Unblock-File .\Invoke-PHPWebshellScan.ps1` if appropriate for your machine's policy. 

## Where files are stored

By default, the working files reside under `%LOCALAPPDATA%\PHPWebshellYara`:

- `tools\yara-4.5.5` — portable YARA executable + compiler, with the downloaded ZIP checked against its published SHA-256 on first installation.
- `rules\<SourceName>` — downloaded, selected raw source rules plus `_source.json` (GitHub repository, branch, archive SHA-256, update timestamp).
- `compiled` — local compilations generated using the matching `yarac` binary. The script never loads third-party compiled rules.
- `reports\<timestamp>` — report set for each scan unless `-OutputDir` is supplied.


Five included sources, selected for PHP/web-shell coverage:

| Source | Upstream repository | Files selected |
| --- | --- | --- |
| Neo23x0 (Nextron) | <https://github.com/Neo23x0/signature-base> | `yara/gen_webshells.yar` |
| Yara-Rules | <https://github.com/Yara-Rules/rules> | All `webshells/*.yar` |
| NSA Cybersecurity | <https://github.com/nsacyber/Mitigating-Web-Shells> | `extended.webshell_detection.yara` |
| PHP Malware Finder | <https://github.com/jvoisin/php-malware-finder> | `data/php.yar`, `data/whitelist.yar`, and `data/whitelists/*.yar` (preserved as includes) |
| RobbySec | <https://github.com/robbysec/yara-rules-and-threat-intelligence> | `Webshell_Obfuscated_Detector.yar` |

The PHP Malware Finder repository was archived in 2024, so its rules are historical rather than actively maintained. Licences differ across rule repositories; check their repository-specific licences before redistributing or embedding their rules. Add custom source `.yar` or `.yara` files under `rules\Local` to load them on the next scan, or edit the `$Sources` array in the script to fetch more curated repositories.

## Outputs

- `files.csv`: **one row per enumerated file**, with status (`Matched`, `NoMatchInLoadedRules`, `SkippedSizeLimit`, `SkippedReparsePoint`), size, matching rules, rule sources, count, and SHA-256 for matches (or all eligible files with `-HashAll`).
- `hits.csv`: **one row per matching rule per file**, with rule identifier, tags, rule-source repository label, rule file and matched file SHA-256.
- `report.json`: summary, source rule paths and hashes, rejected rule files, scan issues, all files and all hits.
- `rule-errors.csv` (when relevant): rejected rule files with compiler errors.
- `scan-errors.csv` (when relevant): failed or incomplete rule scans, unexpected output, inaccessible files and hash/enumeration problems.

The default scan uses `-r` (recursive) and `-N` (do not follow symlinks). All extensions are scanned, not just `.php`, because attackers may hide PHP in images, `.phtml`, `.inc`, or files with misleading extensions. The default file-size limit is **25 MiB**; large files and reparse-point files are listed as skipped. `NoMatchInLoadedRules` **does not mean benign** and is less meaningful when the report lists compilation or scanning failures.

The console only lists files with rule hits; the CSV lists all enumerated files including no-hit and skipped statuses. SHA-256 values support forensic triage and deduplication; they do not constitute proof that a file is malicious.

