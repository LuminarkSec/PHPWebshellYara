#Requires -Version 5.1
<#
.SYNOPSIS
  Portable YARA-based PHP web-shell hunter for Windows 11.
.DESCRIPTION
  Installs an official Windows YARA build (SHA-256 checked) into LOCALAPPDATA,
  downloads selected web-shell rules from five GitHub repositories, validates
  each entry-point rule with yarac, recursively scans a folder, and writes per-file
  and per-match CSV and JSON reports. No PHP samples are executed or modified.
.EXAMPLE
  .\Invoke-PHPWebshellScan.ps1 -ScanPath 'D:\Samples\PHP'
.EXAMPLE
  .\Invoke-PHPWebshellScan.ps1 -UpdateRules
.EXAMPLE
  .\Invoke-PHPWebshellScan.ps1 -ScanPath 'D:\Samples\PHP' -Offline -HashAll
.EXAMPLE
  .\Invoke-PHPWebshellScan.ps1 -ScanPath 'D:\Samples' -YaraExe 'C:\Tools\YARA\yara64.exe'
.NOTES
  The latest YARA source release may not supply Windows binaries. This
  script pins the official v4.5.5 Windows x64 release with a known checksum.
  Set -YaraExe to use a newer build with its matching yarac executable.
  Rules are fetched from moving GitHub branches; review before high-trust use.
#>
[CmdletBinding()]
param(
    [string] $ScanPath,
    [switch] $UpdateRules,
    [switch] $Offline,
    [switch] $HashAll,
    [ValidateRange(0,2048)] [int] $MaxFileSizeMB = 25,
    [string] $YaraExe,
    [string] $DataDir = (Join-Path $env:LOCALAPPDATA 'PHPWebshellYara'),
    [string] $OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Only these vetted repository LOCATIONS are downloaded. Repository content can
# change; the scanner never runs scripts/binaries from these archives.
$Sources = @(
    [pscustomobject]@{ Name='Neo23x0'; Repo='Neo23x0/signature-base'; Branch='master'; Picks=@('yara/gen_webshells.yar') },
    [pscustomobject]@{ Name='YaraRules'; Repo='Yara-Rules/rules'; Branch='master'; Picks=@('webshells/*.yar') },
    [pscustomobject]@{ Name='NSACyber'; Repo='nsacyber/Mitigating-Web-Shells'; Branch='master'; Picks=@('extended.webshell_detection.yara') },
    # php.yar includes whitelist.yar; the latter includes whitelists/*.yar.
    # Cache the relative directory layout, and compile only the php.yar entry point.
    [pscustomobject]@{ Name='PHPMalwareFinder'; Repo='jvoisin/php-malware-finder'; Branch='master'; Picks=@('data/php.yar','data/whitelist.yar','data/whitelists/*.yar'); CacheRoot='data'; EntryPoints=@('php.yar'); RequiredCache=@('php.yar','whitelist.yar','whitelists\custom.yar') },
    [pscustomobject]@{ Name='RobbySec'; Repo='robbysec/yara-rules-and-threat-intelligence'; Branch='main'; Picks=@('Webshell_Obfuscated_Detector.yar') }
)

# Verified upstream YARA Windows x64 archive, 30 October 2025.
$YaraArchiveUrl = 'https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip'
$YaraArchiveSHA256 = '352396c8a3d9b31b157a4820abd3b9347fc934a2314cdda8a4f566a5570163e4'
$ToolsDir = Join-Path $DataDir 'tools'
$RulesDir = Join-Path $DataDir 'rules'
$BuildDir = Join-Path $DataDir 'compiled'
foreach ($folder in @($DataDir,$ToolsDir,$RulesDir,$BuildDir)) {
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }
}

function Quote-WinArg {
    param([AllowEmptyString()][string] $Value)
    if ($Value -ne '' -and $Value -notmatch '[\s"]') { return $Value }
    $result = '"'
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            $result += ('\' * (2 * $slashes + 1)) + '"'
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { $result += ('\' * $slashes); $slashes = 0 }
        $result += $character
    }
    if ($slashes -gt 0) { $result += ('\' * (2 * $slashes)) }
    return ($result + '"')
}

function Run-Tool {
    param([string] $Executable, [string[]] $Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Executable
    $psi.Arguments = (@($Arguments | ForEach-Object { Quote-WinArg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    try {
        # Read stderr asynchronously to avoid blocking on full OS pipe buffers.
        $stderrRead = $process.StandardError.ReadToEndAsync()
        $stdoutText = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdoutText
            Stderr = $stderrRead.GetAwaiter().GetResult()
        }
    } finally { $process.Dispose() }
}

function Install-PortableYara {
    $destination = Join-Path $ToolsDir 'yara-4.5.5'
    $existing = @(Get-ChildItem -LiteralPath $destination -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('yara64.exe','yara.exe') } | Select-Object -First 1)
    if ($existing.Count -gt 0) {
        $expectedCompiler = if ($existing[0].Name -ieq 'yara64.exe') { 'yarac64.exe' } else { 'yarac.exe' }
        if (Test-Path -LiteralPath (Join-Path $existing[0].DirectoryName $expectedCompiler) -PathType Leaf) {
            return $existing[0].FullName
        }
        Write-Warning 'Cached YARA installation is incomplete; reinstalling.'
    }
    if ($Offline) { throw 'No cached YARA executable exists and -Offline was specified.' }
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'This installer needs 64-bit Windows.' }

    Write-Host '[setup] Downloading official YARA 4.5.5 x64 binary...' -ForegroundColor Cyan
    $tempZip = Join-Path ([IO.Path]::GetTempPath()) ('yara-' + [guid]::NewGuid().ToString('N') + '.zip')
    $tempDir = Join-Path ([IO.Path]::GetTempPath()) ('yara-' + [guid]::NewGuid().ToString('N'))
    try {
        Invoke-WebRequest -Uri $YaraArchiveUrl -OutFile $tempZip -UseBasicParsing
        $actualHash = (Get-FileHash -LiteralPath $tempZip -Algorithm SHA256).Hash
        if ($actualHash -ine $YaraArchiveSHA256) { throw 'YARA download SHA-256 does not match the upstream release checksum.' }
        Expand-Archive -LiteralPath $tempZip -DestinationPath $tempDir -Force
        $binary = @(Get-ChildItem -LiteralPath $tempDir -File -Recurse |
            Where-Object { $_.Name -in @('yara64.exe','yara.exe') } | Select-Object -First 1)
        if ($binary.Count -eq 0) { throw 'Downloaded YARA archive contains no expected executable.' }
        $compilerName = if ($binary[0].Name -ieq 'yara64.exe') { 'yarac64.exe' } else { 'yarac.exe' }
        if (-not (Test-Path -LiteralPath (Join-Path $binary[0].DirectoryName $compilerName) -PathType Leaf)) {
            throw "Downloaded YARA archive lacks $compilerName."
        }
        if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Recurse -Force }
        Copy-Item -LiteralPath $tempDir -Destination $destination -Recurse -Force
        return (Join-Path $destination ($binary[0].FullName.Substring($tempDir.Length).TrimStart('\')))
    } finally {
        Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Download-RuleSource {
    param($Source)
    $destination = Join-Path $RulesDir $Source.Name
    $zipPath = Join-Path ([IO.Path]::GetTempPath()) ('yrules-' + [guid]::NewGuid().ToString('N') + '.zip')
    $unzipDir = Join-Path ([IO.Path]::GetTempPath()) ('yrules-' + [guid]::NewGuid().ToString('N'))
    $stagedRules = Join-Path $RulesDir ($Source.Name + '-incoming-' + [guid]::NewGuid().ToString('N'))
    $backup = Join-Path $RulesDir ($Source.Name + '-previous-' + [guid]::NewGuid().ToString('N'))
    $archiveUrl = "https://codeload.github.com/$($Source.Repo)/zip/refs/heads/$($Source.Branch)"
    try {
        Write-Host "[rules] Updating $($Source.Name)..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $archiveUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -LiteralPath $zipPath -DestinationPath $unzipDir -Force
        $repoRoot = @(Get-ChildItem -LiteralPath $unzipDir -Directory | Select-Object -First 1)
        if ($repoRoot.Count -eq 0) { throw 'GitHub archive has no repository root.' }
        New-Item -ItemType Directory -Path $stagedRules -Force | Out-Null
        $copied = 0
        foreach ($pick in $Source.Picks) {
            $normalised = $pick.Replace('/', '\')
            # Most rule collections are intentionally flattened into the cache.
            # A source with CacheRoot preserves subfolders under that root so
            # YARA include statements resolve correctly.
            $cacheSubDir = ''
            if ($Source.PSObject.Properties.Name -contains 'CacheRoot') {
                $prefix = $Source.CacheRoot.TrimEnd('\') + '\'
                if (-not $normalised.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Rule path '$pick' is outside its configured cache root."
                }
                $withinRoot = $normalised.Substring($prefix.Length)
                $cacheSubDir = Split-Path -Path $withinRoot -Parent
            }
            $targetDir = if ($cacheSubDir) { Join-Path $stagedRules $cacheSubDir } else { $stagedRules }
            if (-not (Test-Path -LiteralPath $targetDir -PathType Container)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }
            if ($normalised.EndsWith('*.yar')) {
                $relativeDir = Split-Path -Path $normalised -Parent
                $selectionDir = Join-Path $repoRoot[0].FullName $relativeDir
                if (-not (Test-Path -LiteralPath $selectionDir -PathType Container)) {
                    throw "Required YARA folder absent: $pick"
                }
                $selected = @(Get-ChildItem -LiteralPath $selectionDir -File -Filter '*.yar')
                if ($selected.Count -eq 0) { throw "No .yar files matched: $pick" }
                foreach ($entry in $selected) {
                    Copy-Item -LiteralPath $entry.FullName -Destination (Join-Path $targetDir $entry.Name) -Force
                    $copied++
                }
            } else {
                $absolute = Join-Path $repoRoot[0].FullName $normalised
                if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
                    throw "Required rule file absent: $pick"
                }
                Copy-Item -LiteralPath $absolute -Destination (Join-Path $targetDir (Split-Path $absolute -Leaf)) -Force
                $copied++
            }
        }
        $manifest = [pscustomobject]@{
            Source = $Source.Name; GitHub = "https://github.com/$($Source.Repo)"
            Branch = $Source.Branch; DownloadedUTC = [DateTime]::UtcNow.ToString('o')
            ArchiveSHA256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
            RuleFiles = $copied
        }
        $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $stagedRules '_source.json') -Encoding UTF8
        # Never destroy the last working cached ruleset until staging succeeds.
        if (Test-Path -LiteralPath $destination) { Move-Item -LiteralPath $destination -Destination $backup }
        try { Move-Item -LiteralPath $stagedRules -Destination $destination }
        catch {
            if (Test-Path -LiteralPath $backup) { Move-Item -LiteralPath $backup -Destination $destination }
            throw
        }
        Write-Host "[rules] $($Source.Name): cached $copied file(s)" -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "Could not update $($Source.Name): $($_.Exception.Message)"
        return $false
    } finally {
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $unzipDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stagedRules -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($YaraExe) {
    $YaraExe = (Resolve-Path -LiteralPath $YaraExe -ErrorAction Stop).ProviderPath
} else {
    $YaraExe = Install-PortableYara
}
$YaraBaseName = [IO.Path]::GetFileName($YaraExe)
$compilerName = if ($YaraBaseName -ieq 'yara64.exe') { 'yarac64.exe' } elseif ($YaraBaseName -ieq 'yara.exe') { 'yarac.exe' } else { throw 'YARA executable must be named yara.exe or yara64.exe.' }
$YaracExe = Join-Path (Split-Path -Path $YaraExe -Parent) $compilerName
if (-not (Test-Path -LiteralPath $YaracExe -PathType Leaf)) { throw "Matching compiler was not found: $YaracExe" }
$version = Run-Tool -Executable $YaraExe -Arguments @('--version')
if ($version.ExitCode -ne 0) { throw "YARA could not be launched: $($version.Stderr)" }
Write-Host "[setup] YARA version $($version.Stdout.Trim())" -ForegroundColor Green

foreach ($source in $Sources) {
    $dest = Join-Path $RulesDir $source.Name
    $existingRules = @(Get-ChildItem -LiteralPath $dest -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.yar','.yara') })
    $cacheIncomplete = $false
    if ($source.PSObject.Properties.Name -contains 'RequiredCache') {
        foreach ($requiredRelative in $source.RequiredCache) {
            if (-not (Test-Path -LiteralPath (Join-Path $dest $requiredRelative) -PathType Leaf)) {
                $cacheIncomplete = $true
                break
            }
        }
    }
    if ($UpdateRules -or $existingRules.Count -eq 0 -or $cacheIncomplete) {
        if ($Offline) {
            if ($cacheIncomplete) { Write-Warning "[offline] $($source.Name) cache is incomplete. Run online with -UpdateRules to repair it." }
            if ($existingRules.Count -eq 0) { Write-Warning "[offline] $($source.Name) is not cached." }
            else { Write-Host "[offline] Reusing $($source.Name)" }
        } else {
            $null = Download-RuleSource -Source $source
        }
    }
}

if (-not $ScanPath) {
    Write-Host '[ready] Installation/cache update complete. To scan, supply -ScanPath <folder>.' -ForegroundColor Green
    return
}
if (-not (Test-Path -LiteralPath $ScanPath -PathType Container)) { throw "Scan directory does not exist: $ScanPath" }
$ScanPath = (Resolve-Path -LiteralPath $ScanPath).ProviderPath
if (-not $OutputDir) { $OutputDir = Join-Path (Join-Path $DataDir 'reports') (Get-Date -Format 'yyyyMMdd-HHmmss-fff') }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).ProviderPath
if ($OutputDir.StartsWith(($ScanPath.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
    Write-Warning 'The report directory is inside the scan directory. Old reports may be scanned; choose an outside -OutputDir.'
}

$ruleFiles = @(Get-ChildItem -LiteralPath $RulesDir -File -Recurse -ErrorAction Stop |
    Where-Object { $_.Extension -in @('.yar','.yara') } | Sort-Object FullName)
if ($ruleFiles.Count -eq 0) { throw 'No cached .yar/.yara rules are available. Re-run without -Offline.' }
# Each source file compiles separately: incompatible or duplicate third-party rules
# cannot prevent all the other source files from being scanned.
$compiled = [System.Collections.Generic.List[object]]::new()
$ruleErrors = [System.Collections.Generic.List[object]]::new()
$scanErrors = [System.Collections.Generic.List[object]]::new()
$hitRecords = [System.Collections.Generic.List[object]]::new()

Write-Host "[compile] Validating YARA entry-point rules from $($ruleFiles.Count) cached .yar/.yara file(s)..." -ForegroundColor Cyan
$ruleNumber = 0
foreach ($ruleFile in $ruleFiles) {
    $relative = $ruleFile.FullName.Substring($RulesDir.Length).TrimStart('\')
    $sourceName = ($relative -split '[\\/]')[0]
    # Some rules in the cache exist only to satisfy include statements.
    # Compiling one of those independently is not useful and can fail.
    $sourceConfig = @($Sources | Where-Object { $_.Name -eq $sourceName } | Select-Object -First 1)
    if ($sourceConfig.Count -gt 0 -and ($sourceConfig[0].PSObject.Properties.Name -contains 'EntryPoints')) {
        $relativeWithinSource = $relative.Substring($sourceName.Length).TrimStart('\')
        if ($relativeWithinSource -notin $sourceConfig[0].EntryPoints) { continue }
    }
    $ruleNumber++
    $compiledPath = Join-Path $BuildDir ('rule-{0:D4}.yarac' -f $ruleNumber)
    Remove-Item -LiteralPath $compiledPath -Force -ErrorAction SilentlyContinue
    try {
        $result = Run-Tool -Executable $YaracExe -Arguments @($ruleFile.FullName, $compiledPath)
        if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $compiledPath -PathType Leaf)) {
            $reason = ($result.Stderr + ' ' + $result.Stdout).Trim()
            if (-not $reason) { $reason = 'Compiler returned an error.' }
            throw $reason
        }
        $compiled.Add([pscustomobject]@{ Source=$sourceName; RuleFile=$relative; Compiled=$compiledPath; SHA256=(Get-FileHash -LiteralPath $ruleFile.FullName -Algorithm SHA256).Hash })
    } catch {
        $ruleErrors.Add([pscustomobject]@{ Source=$sourceName; RuleFile=$relative; Error=$_.Exception.Message })
        Write-Warning "Skipped incompatible rule file '$relative': $($_.Exception.Message)"
    }
}
if ($compiled.Count -eq 0) { throw 'All rule files failed compilation. Check rule syntax, dependencies and YARA version.' }
Write-Host "[compile] Ready: $($compiled.Count) rule file(s); skipped: $($ruleErrors.Count)." -ForegroundColor Green

$yaraFlags = @('-C','-r','-N','-g','-w')
if ($MaxFileSizeMB -gt 0) {
    $limitBytes = [long]$MaxFileSizeMB * 1024 * 1024
    $yaraFlags += ('--skip-larger=' + $limitBytes)
} else { $limitBytes = 0 }

$i = 0
foreach ($rule in $compiled) {
    $i++
    Write-Progress -Activity 'Scanning all files recursively with YARA' -Status "$i / $($compiled.Count): $($rule.RuleFile)" -PercentComplete (100 * $i / $compiled.Count)
    try {
        $arguments = @($yaraFlags) + @($rule.Compiled, $ScanPath)
        $result = Run-Tool -Executable $YaraExe -Arguments $arguments
        if ($result.ExitCode -ne 0) {
            $message = ($result.Stderr + ' ' + $result.Stdout).Trim()
            $scanErrors.Add([pscustomobject]@{ RuleFile=$rule.RuleFile; Error=$message })
            Write-Warning "YARA failed while scanning with $($rule.RuleFile): $message"
            continue
        }
        if ($result.Stderr.Trim()) {
            $scanErrors.Add([pscustomobject]@{ RuleFile=$rule.RuleFile; Error=$result.Stderr.Trim() })
        }
        foreach ($line in ($result.Stdout -split '\r?\n')) {
            if (-not $line.Trim()) { continue }
            # YARA's -g output: rule_name [optional_tags] absolute_file_path
            $m = [regex]::Match($line, '^(?<rule>[A-Za-z_][A-Za-z0-9_]*)(?: \[(?<tags>[^\]]*)\])? (?<file>.+)$')
            if (-not $m.Success) {
                $scanErrors.Add([pscustomobject]@{ RuleFile=$rule.RuleFile; Error="Unexpected YARA output: $line" })
                continue
            }
            $matchedFile = $m.Groups['file'].Value
            if (-not [IO.File]::Exists($matchedFile)) {
                $scanErrors.Add([pscustomobject]@{ RuleFile=$rule.RuleFile; Error="Match path no longer exists or could not be interpreted: $line" })
                continue
            }
            $hitRecords.Add([pscustomobject]@{
                File = [IO.Path]::GetFullPath($matchedFile)
                Rule = $m.Groups['rule'].Value
                Tags = $m.Groups['tags'].Value
                Source = $rule.Source
                RuleFile = $rule.RuleFile
                SHA256 = $null
            })
        }
    } catch {
        $scanErrors.Add([pscustomobject]@{ RuleFile=$rule.RuleFile; Error=$_.Exception.Message })
        Write-Warning "YARA scan error for $($rule.RuleFile): $($_.Exception.Message)"
    }
}
Write-Progress -Activity 'Scanning all files recursively with YARA' -Completed

$byFile = @{}
foreach ($hit in $hitRecords) {
    if (-not $byFile.ContainsKey($hit.File)) { $byFile[$hit.File] = [System.Collections.Generic.List[object]]::new() }
    $byFile[$hit.File].Add($hit)
}

$enumerationErrors = @()
$foundFiles = @(Get-ChildItem -LiteralPath $ScanPath -File -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable +enumerationErrors | Sort-Object FullName)
$perFile = [System.Collections.Generic.List[object]]::new()
foreach ($file in $foundFiles) {
    $fpath = $file.FullName
    $status = 'NoMatchInLoadedRules'
    $fileMatches = @()
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        $status = 'SkippedReparsePoint'
    } elseif ($limitBytes -gt 0 -and $file.Length -ge $limitBytes) {
        $status = 'SkippedSizeLimit'
    } elseif ($byFile.ContainsKey($fpath)) {
        $status = 'Matched'
        $fileMatches = $byFile[$fpath].ToArray()
    }
    $hash = ''
    if (($HashAll -and $status -ne 'SkippedReparsePoint' -and $status -ne 'SkippedSizeLimit') -or $status -eq 'Matched') {
        try { $hash = (Get-FileHash -LiteralPath $fpath -Algorithm SHA256).Hash }
        catch { $scanErrors.Add([pscustomobject]@{ RuleFile='file_hash'; Error="$fpath : $($_.Exception.Message)" }) }
    }
    foreach ($hit in $fileMatches) { $hit.SHA256 = $hash }
    $perFile.Add([pscustomobject]@{
        File = $fpath; Status = $status; Bytes = $file.Length; SHA256 = $hash
        MatchCount = $fileMatches.Count
        Rules = (($fileMatches | ForEach-Object { $_.Rule } | Select-Object -Unique) -join '; ')
        Sources = (($fileMatches | ForEach-Object { $_.Source } | Select-Object -Unique) -join '; ')
    })
}
foreach ($e in $enumerationErrors) { $scanErrors.Add([pscustomobject]@{ RuleFile='file_enumeration'; Error=[string]$e }) }
# Preserve matches if a file vanished between YARA scanning and enumeration.
$seenFiles = @{}
foreach ($record in $perFile) { $seenFiles[$record.File] = $true }
foreach ($path in $byFile.Keys) {
    if (-not $seenFiles.ContainsKey($path)) {
        $perFile.Add([pscustomobject]@{ File=$path; Status='MatchedFileVanished'; Bytes=$null; SHA256=''; MatchCount=$byFile[$path].Count; Rules=(($byFile[$path] | ForEach-Object Rule) -join '; '); Sources=(($byFile[$path] | ForEach-Object Source | Select-Object -Unique) -join '; ') })
    }
}

$sortedHits = @($hitRecords | Sort-Object File,Source,Rule)
$sortedFiles = @($perFile | Sort-Object File)
$hitsCsv = Join-Path $OutputDir 'hits.csv'
$filesCsv = Join-Path $OutputDir 'files.csv'
if ($sortedHits.Count -gt 0) { $sortedHits | Export-Csv -LiteralPath $hitsCsv -NoTypeInformation -Encoding UTF8 }
else { '"File","Rule","Tags","Source","RuleFile","SHA256"' | Set-Content -LiteralPath $hitsCsv -Encoding UTF8 }
if ($sortedFiles.Count -gt 0) { $sortedFiles | Export-Csv -LiteralPath $filesCsv -NoTypeInformation -Encoding UTF8 }
else { '"File","Status","Bytes","SHA256","MatchCount","Rules","Sources"' | Set-Content -LiteralPath $filesCsv -Encoding UTF8 }
if ($ruleErrors.Count -gt 0) { $ruleErrors | Export-Csv -LiteralPath (Join-Path $OutputDir 'rule-errors.csv') -NoTypeInformation -Encoding UTF8 }
if ($scanErrors.Count -gt 0) { $scanErrors | Export-Csv -LiteralPath (Join-Path $OutputDir 'scan-errors.csv') -NoTypeInformation -Encoding UTF8 }

$matchedFilesCount = @($sortedFiles | Where-Object { $_.Status -in @('Matched','MatchedFileVanished') }).Count
$summary = [ordered]@{
    TimestampUTC = [DateTime]::UtcNow.ToString('o')
    ScanPath = $ScanPath; OutputDir = $OutputDir
    YaraVersion = $version.Stdout.Trim(); YaraExecutable = $YaraExe
    RuleFilesLoaded = $compiled.Count; RuleFilesRejected = $ruleErrors.Count
    RuleScansWithWarningsOrErrors = $scanErrors.Count
    FilesEnumerated = $sortedFiles.Count
    FilesEligible = @($sortedFiles | Where-Object { $_.Status -notin @('SkippedSizeLimit','SkippedReparsePoint') }).Count
    FilesWithMatches = $matchedFilesCount; RuleMatches = $sortedHits.Count
    MaxFileSizeMB = $MaxFileSizeMB
}
$report = [ordered]@{ Summary=$summary; RuleFiles=$compiled.ToArray(); RejectedRules=$ruleErrors.ToArray(); ScanIssues=$scanErrors.ToArray(); Files=$sortedFiles; Hits=$sortedHits }
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDir 'report.json') -Encoding UTF8

Write-Host "`n========== YARA WEB-SHELL SCAN ==========" -ForegroundColor Cyan
Write-Host "Folder: $ScanPath"
Write-Host "Eligible files: $($summary.FilesEligible) | Matched files: $matchedFilesCount | Rule hits: $($sortedHits.Count)"
Write-Host "Rule files: $($compiled.Count) accepted, $($ruleErrors.Count) rejected; scan issues: $($scanErrors.Count)"
if ($sortedHits.Count -gt 0) {
    foreach ($fileGroup in ($sortedHits | Group-Object File)) {
        Write-Host "`n[HIT] $($fileGroup.Name)" -ForegroundColor Yellow
        foreach ($hit in $fileGroup.Group) {
            Write-Host "  $($hit.Source) / $($hit.Rule)  [$($hit.RuleFile)]"
        }
        Write-Host "  SHA256: $($fileGroup.Group[0].SHA256)"
    }
} else { Write-Host '[no matches] No rule matches were reported by the successfully scanned rule files.' -ForegroundColor Green }
Write-Host "`nReports: $OutputDir" -ForegroundColor Cyan
Write-Host '  files.csv | hits.csv | report.json (plus error CSVs when relevant)'
if ($ruleErrors.Count -gt 0 -or $scanErrors.Count -gt 0) {
    Write-Warning 'Scan completeness was affected by rejected rules or scan issues. Review report.json and error CSVs.'
}
