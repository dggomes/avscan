<#
.SYNOPSIS
  scan-av - on-demand multi-engine antivirus scanner for Windows.
  Runs ClamAV (clamscan) and/or Emsisoft Emergency Kit (a2cmd) over folders
  and large game archives, working around ClamAV's 2 GiB-per-file limit by
  extracting only the executable "threat surface" with 7-Zip before scanning.

.DESCRIPTION
  First run auto-detects the scanners + 7-Zip, asks which folders to scan, and
  saves everything to a JSON config. Later runs just read the config.

  Mirrors the macOS 'scan-archive' workflow, but cross-engine:
    - Archives (.rar/.7z/.zip): extract exec/script files, scan, clean up.
    - Folders: scan in place.
    - ClamAV size-limit skips (Heuristics.Limits.Exceeded) are reported as
      "skipped", NOT as malware.
    - Running both engines: agreement = high confidence, disagreement = the
      files worth checking on VirusTotal (e.g. Denuvo false positives).

.PARAMETER Install
  Copy this script into %LOCALAPPDATA%\ScanAV, add it to your PATH, then configure.
.PARAMETER Configure
  (Re)run the first-run setup wizard and rewrite the config.
.PARAMETER Path
  One or more files/folders to scan, overriding the configured folders.
.PARAMETER Full
  Extract & scan EVERY file in an archive (not just executables). Slower.
.PARAMETER Engine
  clamav | emsisoft | both  (default: whatever the config has enabled)
.PARAMETER Update
  Update virus definitions first (freshclam / a2cmd /update) before scanning.
.PARAMETER Help
  Show this help.

.EXAMPLE
  .\scan-av.ps1 -Install
.EXAMPLE
  scan-av                       # scan all configured folders
.EXAMPLE
  scan-av -Path 'D:\Downloads\Game.rar' -Update
#>

[CmdletBinding()]
param(
  [switch]$Install,
  [switch]$InstallEngines,
  [switch]$Configure,
  [string[]]$Path,
  [switch]$Full,
  [ValidateSet('clamav','emsisoft','both','config')] [string]$Engine = 'config',
  [switch]$Update,
  [switch]$Help
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- paths / dirs
$AppDir  = Join-Path $env:LOCALAPPDATA 'ScanAV'
$CfgFile = Join-Path $AppDir 'config.json'
$LogDir  = Join-Path $AppDir 'logs'
$EngDir  = Join-Path $AppDir 'engines'
$ArchiveExt = @('.rar','.7z','.zip','.zipx','.001','.tar','.gz','.cab','.iso')
$DefaultExecExt = @('exe','dll','msi','bat','cmd','ps1','vbs','scr','com','sys','jar','lnk','hta','js','wsf','ocx','cpl','efi')

# ---------------------------------------------------------------- pretty print
function Hr   { Write-Host ('=' * 64) -ForegroundColor DarkGray }
function Sec  ($t){ Hr; Write-Host $t -ForegroundColor Cyan; Hr }
function Info ($t){ Write-Host "  $t" }
function Ok   ($t){ Write-Host "  $t" -ForegroundColor Green }
function Warn ($t){ Write-Host "  $t" -ForegroundColor Yellow }
function Bad  ($t){ Write-Host "  $t" -ForegroundColor Red }

if ($Help) { Get-Help $PSCommandPath -Detailed; return }

# ---------------------------------------------------------------- tool finder
function Find-Tool {
  param([string]$Exe, [string[]]$Candidates)
  # 1) already on PATH?
  $cmd = Get-Command $Exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  # 2) known install locations
  foreach ($c in $Candidates) {
    if ($c -and (Test-Path $c)) { return (Resolve-Path $c).Path }
  }
  # 3) bounded search of likely roots (last resort, can be slow)
  $roots = @($EngDir, "$env:SystemDrive\", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads",
             "$env:SystemDrive\EEK", "$env:ProgramData", "$env:ProgramFiles", ${env:ProgramFiles(x86)})
  foreach ($r in ($roots | Select-Object -Unique)) {
    if (-not (Test-Path $r)) { continue }
    try {
      $hit = Get-ChildItem -Path $r -Filter $Exe -Recurse -Depth 4 -ErrorAction SilentlyContinue |
             Select-Object -First 1
      if ($hit) { return $hit.FullName }
    } catch {}
  }
  return $null
}

function Ask {
  param([string]$Prompt, [string]$Default)
  if ($Default) { $r = Read-Host "$Prompt [$Default]" } else { $r = Read-Host $Prompt }
  if ([string]::IsNullOrWhiteSpace($r)) { return $Default } else { return $r.Trim('"') }
}
function AskYesNo { param([string]$Prompt,[bool]$Default=$true)
  $d = if($Default){'Y/n'}else{'y/N'}; $r = Read-Host "$Prompt [$d]"
  if ([string]::IsNullOrWhiteSpace($r)) { return $Default }
  return ($r -match '^[Yy]')
}

# ---------------------------------------------------------------- configure
function Invoke-Configure {
  param([hashtable]$Pre = @{})
  Sec 'scan-av  -  first-run configuration'
  New-Item -ItemType Directory -Force -Path $AppDir, $LogDir | Out-Null

  Info 'Detecting tools (this can take a moment the first time)...'
  $sevenZ  = if ($Pre.seven) { $Pre.seven } else { Find-Tool '7z.exe'      @("$EngDir\7-Zip\7z.exe", "$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe") }
  $clam    = if ($Pre.clam)  { $Pre.clam }  else { Find-Tool 'clamscan.exe' @("$EngDir\ClamAV\clamscan.exe", "$env:ProgramFiles\ClamAV\clamscan.exe", "${env:ProgramFiles(x86)}\ClamAV\clamscan.exe", "$env:SystemDrive\ClamAV\clamscan.exe", "$env:ProgramData\chocolatey\bin\clamscan.exe") }
  $fresh   = if ($Pre.fresh) { $Pre.fresh } else { Find-Tool 'freshclam.exe' @("$EngDir\ClamAV\freshclam.exe", "$env:ProgramFiles\ClamAV\freshclam.exe", "${env:ProgramFiles(x86)}\ClamAV\freshclam.exe", "$env:SystemDrive\ClamAV\freshclam.exe") }
  $a2      = if ($Pre.a2)    { $Pre.a2 }    else { Find-Tool 'a2cmd.exe'    @("$EngDir\EEK\bin\a2cmd.exe", "$env:SystemDrive\EEK\bin\a2cmd.exe", "$env:ProgramData\EEK\bin\a2cmd.exe", "$env:USERPROFILE\Desktop\EEK\bin\a2cmd.exe", "$env:USERPROFILE\Downloads\EEK\bin\a2cmd.exe", "$env:ProgramFiles\Emsisoft Emergency Kit\bin\a2cmd.exe") }

  Write-Host ''
  Info 'Confirm or correct each path (Enter to accept, blank/"-" to disable):'
  $sevenZ = Ask '  7-Zip  (7z.exe)'        $sevenZ
  $clam   = Ask '  ClamAV (clamscan.exe)'  $clam
  $fresh  = Ask '  ClamAV (freshclam.exe)' $fresh
  $a2     = Ask '  Emsisoft (a2cmd.exe)'   $a2
  foreach ($v in 'sevenZ','clam','fresh','a2') { if ((Get-Variable $v).Value -eq '-') { Set-Variable $v '' } }

  if (-not $sevenZ) { Warn '7-Zip not set - archive (.rar/.7z) scanning will be disabled; folders still work.' }
  $useClam = [bool]$clam -and (AskYesNo '  Enable ClamAV engine?'   $([bool]$clam))
  $useEms  = [bool]$a2   -and (AskYesNo '  Enable Emsisoft engine?' $([bool]$a2))
  if (-not ($useClam -or $useEms)) { Bad 'No engine enabled. Install ClamAV and/or Emsisoft Emergency Kit, then re-run -Configure.'; return $null }

  Write-Host ''
  Info 'Which folders should "scan-av" check by default? (one per line, blank to finish)'
  $folders = @()
  while ($true) {
    $f = Read-Host '  folder'
    if ([string]::IsNullOrWhiteSpace($f)) { break }
    $f = $f.Trim('"')
    if (Test-Path $f) { $folders += (Resolve-Path $f).Path } else { Warn "    not found, added anyway: $f"; $folders += $f }
  }

  Write-Host ''
  $modeFull = AskYesNo '  Scan FULL archive contents instead of just executables? (slower)' $false
  $maxFile  = [int](Ask '  ClamAV max single-file size in MB (<=2000)' '2000')
  $maxScan  = [int](Ask '  ClamAV max total scan size per container in MB' '4000')

  $cfg = [ordered]@{
    version   = 1
    tools     = [ordered]@{ sevenZip=$sevenZ; clamscan=$clam; freshclam=$fresh; a2cmd=$a2 }
    engines   = [ordered]@{ clamav=$useClam; emsisoft=$useEms }
    scanFolders = $folders
    options   = [ordered]@{
      mode='exec'; maxFileSizeMB=$maxFile; maxScanSizeMB=$maxScan
      execExtensions=$DefaultExecExt; tempDir=''
    }
  }
  if ($modeFull) { $cfg.options.mode = 'full' }

  ($cfg | ConvertTo-Json -Depth 6) | Set-Content -Path $CfgFile -Encoding UTF8
  Write-Host ''
  Ok "Saved config -> $CfgFile"
  Info "Engines: ClamAV=$useClam  Emsisoft=$useEms   Folders: $($folders.Count)   Mode: $($cfg.options.mode)"
  return $cfg
}

function Load-Config {
  if (-not (Test-Path $CfgFile)) { return $null }
  return (Get-Content $CfgFile -Raw | ConvertFrom-Json)
}

# ---------------------------------------------------------------- engine auto-install
function Ensure-Tls { try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {} }
function Get-File { param($Url,$Out) Ensure-Tls; Info "    download: $Url"; Invoke-WebRequest -Uri $Url -OutFile $Out -UseBasicParsing }

function Install-SevenZip {
  Info '7-Zip:'
  $found = (Get-Command 7z.exe -ErrorAction SilentlyContinue).Source
  if (-not $found) { foreach ($p in "$env:ProgramFiles\7-Zip\7z.exe","${env:ProgramFiles(x86)}\7-Zip\7z.exe","$EngDir\7-Zip\7z.exe") { if (Test-Path $p) { $found = $p; break } } }
  if ($found) { Ok "  already present: $found"; return $found }
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    try { winget install -e --id 7zip.7zip --accept-source-agreements --accept-package-agreements 2>$null | Out-Null } catch {}
    foreach ($p in "$env:ProgramFiles\7-Zip\7z.exe","${env:ProgramFiles(x86)}\7-Zip\7z.exe") { if (Test-Path $p) { Ok "  installed via winget"; return $p } }
  }
  try {  # NSIS silent install into a user dir (no admin needed)
    $page = (Invoke-WebRequest 'https://www.7-zip.org/download.html' -UseBasicParsing).Content
    $m = [regex]::Match($page,'a/(7z\d+-x64\.exe)')
    if ($m.Success) {
      $dl = Join-Path $env:TEMP $m.Groups[1].Value
      Get-File "https://www.7-zip.org/$($m.Value)" $dl
      $target = Join-Path $EngDir '7-Zip'
      Start-Process $dl -ArgumentList '/S',"/D=$target" -Wait
      if (Test-Path "$target\7z.exe") { Ok "  installed: $target\7z.exe"; return "$target\7z.exe" }
    }
  } catch { Warn "  7-Zip auto-install failed: $_" }
  Warn '  Could not auto-install 7-Zip (install manually from https://7-zip.org). Folder scans still work without it.'
  return $null
}

function Install-ClamAV {
  Info 'ClamAV (portable, no admin):'
  $dest = Join-Path $EngDir 'ClamAV'
  $clamExe = Get-ChildItem $dest -Recurse -Filter 'clamscan.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $clamExe) {
    try {
      Ensure-Tls
      $rel = Invoke-RestMethod 'https://api.github.com/repos/Cisco-Talos/clamav/releases/latest' -Headers @{ 'User-Agent'='scan-av' }
      $asset = $rel.assets | Where-Object { $_.name -match 'win\.x64\.zip$' } | Select-Object -First 1
      if (-not $asset) { throw 'no win.x64.zip asset in latest release' }
      $zip = Join-Path $env:TEMP $asset.name
      Get-File $asset.browser_download_url $zip
      New-Item -ItemType Directory -Force $dest | Out-Null
      Expand-Archive -Path $zip -DestinationPath $dest -Force
      $clamExe = Get-ChildItem $dest -Recurse -Filter 'clamscan.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    } catch { Warn "  ClamAV auto-install failed: $_"; return $null }
  }
  if (-not $clamExe) { Warn '  clamscan.exe not found after extract.'; return $null }
  $bin = Split-Path $clamExe.FullName
  Ok "  installed: $($clamExe.FullName)"
  $fresh = Join-Path $bin 'freshclam.exe'
  $dbDir = Join-Path $bin 'database'; New-Item -ItemType Directory -Force $dbDir | Out-Null
  $fcConf = Join-Path $bin 'freshclam.conf'
  if (-not (Test-Path $fcConf)) { "DatabaseDirectory $dbDir`nDatabaseMirror database.clamav.net" | Set-Content $fcConf -Encoding ASCII }
  $freshPath = $null
  if (Test-Path $fresh) {
    $freshPath = $fresh
    Info '  downloading definitions (freshclam, ~300 MB first time)...'
    try { & $fresh "--config-file=$fcConf" --datadir="$dbDir" *> (Join-Path $LogDir 'freshclam_install.log'); Ok '  definitions updated.' }
    catch { Warn "  freshclam failed (run it later): $_" }
  }
  return [pscustomobject]@{ clamscan=$clamExe.FullName; freshclam=$freshPath }
}

function Install-Emsisoft {
  param($SevenZip)
  Info 'Emsisoft Emergency Kit (FREE for private/personal use only):'
  $dest = Join-Path $EngDir 'EEK'
  $a2 = Get-ChildItem $dest -Recurse -Filter 'a2cmd.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($a2) { Ok "  already present: $($a2.FullName)"; return $a2.FullName }
  $sfx = Join-Path $env:TEMP 'EmsisoftEmergencyKit.exe'
  try { Get-File 'https://dl.emsisoft.com/EmsisoftEmergencyKit.exe' $sfx } catch { Warn "  download failed: $_"; return $null }
  New-Item -ItemType Directory -Force $dest | Out-Null
  $extracted = $false
  if ($SevenZip) { try { & $SevenZip x $sfx "-o$dest" '-y' *> $null; $extracted = $true } catch {} }
  if (-not $extracted) {
    Warn '  Could not silently extract (7-Zip needed). Launching the EEK extractor - accept the default folder, then re-run: scan-av -Configure'
    Start-Process $sfx; return $null
  }
  $a2 = Get-ChildItem $dest -Recurse -Filter 'a2cmd.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $a2) { Warn '  a2cmd.exe not found after extraction; run the EEK GUI once, then: scan-av -Configure'; return $null }
  Ok "  installed: $($a2.FullName)"
  Info '  updating Emsisoft definitions (large first-time download)...'
  try { & $a2.FullName '/update' *> (Join-Path $LogDir 'a2update_install.log'); Ok '  definitions updated.' } catch { Warn "  a2cmd /update failed (run later): $_" }
  return $a2.FullName
}

function Install-Engines {
  Sec 'scan-av  -  auto-install engines'
  New-Item -ItemType Directory -Force -Path $EngDir, $LogDir | Out-Null
  Warn 'This downloads 7-Zip, ClamAV and Emsisoft Emergency Kit plus their signature'
  Warn 'databases - several hundred MB total, needs internet. EEK is free for PRIVATE use only.'
  if (-not (AskYesNo 'Proceed with download & install?' $true)) { Warn 'Skipped engine install.'; return }
  $sz   = Install-SevenZip
  $clam = Install-ClamAV
  $a2   = Install-Emsisoft -SevenZip $sz
  Write-Host ''
  Ok 'Engine install finished. Wiring up configuration...'
  Write-Host ''
  $pre = @{}
  if ($sz)   { $pre.seven = $sz }
  if ($clam) { $pre.clam = $clam.clamscan; if ($clam.freshclam) { $pre.fresh = $clam.freshclam } }
  if ($a2)   { $pre.a2 = $a2 }
  Invoke-Configure -Pre $pre | Out-Null
}

# ---------------------------------------------------------------- install
function Invoke-Install {
  param([switch]$WithEngines)
  Sec 'scan-av  -  install'
  New-Item -ItemType Directory -Force -Path $AppDir, $LogDir | Out-Null
  $dest = Join-Path $AppDir 'scan-av.ps1'
  if ($PSCommandPath -and ((Resolve-Path $PSCommandPath).Path -ne (Join-Path $AppDir 'scan-av.ps1'))) {
    Copy-Item -Path $PSCommandPath -Destination $dest -Force
  }
  # convenience wrapper so it runs from cmd / double-click, bypassing exec policy
  $cmd = @"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scan-av.ps1" %*
"@
  Set-Content -Path (Join-Path $AppDir 'scan-av.cmd') -Value $cmd -Encoding ASCII

  # add AppDir to user PATH (persists for future terminals)
  $userPath = [Environment]::GetEnvironmentVariable('Path','User')
  if ($userPath -notlike "*$AppDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$AppDir", 'User')
    Ok "Added to PATH (User): $AppDir"
  } else { Info "Already on PATH: $AppDir" }

  # KEY FIX: also drop a launcher in %LOCALAPPDATA%\Microsoft\WindowsApps, which is
  # already on the default user PATH on Win10/11 -> 'scan-av' works in any NEW
  # terminal with no PATH-refresh dance (Windows Terminal caches PATH at launch).
  $shimDir = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
  $shimMsg = $null
  if (Test-Path $shimDir) {
    $shimCmd = @"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "$AppDir\scan-av.ps1" %*
"@
    try { Set-Content -Path (Join-Path $shimDir 'scan-av.cmd') -Value $shimCmd -Encoding ASCII -ErrorAction Stop
          $shimMsg = "Launcher placed on default PATH: $shimDir\scan-av.cmd" } catch { $shimMsg = $null }
  }
  if ($shimMsg) { Ok $shimMsg }

  # make 'scan-av' usable in THIS session too (User PATH only affects new terminals)
  if ($env:Path -notlike "*$AppDir*") { $env:Path += ";$AppDir" }
  Info "You can run 'scan-av' here now, and in any newly-opened terminal."
  Ok "Installed to $AppDir"
  Write-Host ''
  if ($WithEngines -or (AskYesNo 'Auto-download & install ClamAV + Emsisoft now?' $true)) {
    Install-Engines
  } else {
    Invoke-Configure | Out-Null
  }
}

# ---------------------------------------------------------------- engines
function Run-ClamAV {
  param([string]$Target, [string]$Log, $Cfg)
  $a = @('-r', "--max-filesize=$($Cfg.options.maxFileSizeMB)M",
              "--max-scansize=$($Cfg.options.maxScanSizeMB)M",
              '--alert-exceeds-max=yes', $Target)
  & $Cfg.tools.clamscan @a *> $Log
  $rc = $LASTEXITCODE
  $lines = Get-Content $Log -ErrorAction SilentlyContinue
  $hits  = @($lines | Where-Object { $_ -match ' FOUND$' -and $_ -notmatch 'Heuristics\.Limits\.Exceeded' })
  $skips = @($lines | Where-Object { $_ -match 'Heuristics\.Limits\.Exceeded' })
  [pscustomobject]@{ Engine='ClamAV'; Rc=$rc; Hits=$hits; Skipped=$skips.Count
    Scanned = ([regex]::Match(($lines -join "`n"),'Scanned files:\s*(\d+)').Groups[1].Value) }
}

function Run-Emsisoft {
  param([string]$Target, [string]$Log, $Cfg)
  # We scan an already-extracted folder, so simple recursive/all-files is enough.
  $a = @("/f=$Target", '/s', '/a', '/pup', "/log=$Log", '/loglevel=detailed')
  & $Cfg.tools.a2cmd @a *> (Join-Path $LogDir '_a2cmd_console.txt')
  $rc = $LASTEXITCODE
  $lines = Get-Content $Log -ErrorAction SilentlyContinue
  # a2cmd detection lines contain 'detected:'; summary has 'Scanned'/'Detected'
  $hits = @($lines | Where-Object { $_ -match 'detected:' -and $_ -notmatch '^\s*Detected:' })
  $scanned  = ([regex]::Match(($lines -join "`n"),'Scanned:?\s+(\d+)').Groups[1].Value)
  [pscustomobject]@{ Engine='Emsisoft'; Rc=$rc; Hits=$hits; Skipped=0; Scanned=$scanned }
}

# ---------------------------------------------------------------- extraction
function Extract-Surface {
  param([string]$Archive, [string]$Dest, $Cfg)
  if (-not $Cfg.tools.sevenZip) { throw '7-Zip not configured; cannot extract archives.' }
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  if ($Cfg.options.mode -eq 'full') {
    & $Cfg.tools.sevenZip x $Archive "-o$Dest" '-y' *> $null
  } else {
    $inc = $Cfg.options.execExtensions | ForEach-Object { "-ir!*.$_" }
    & $Cfg.tools.sevenZip x $Archive "-o$Dest" @inc '-y' *> $null
  }
}

# ---------------------------------------------------------------- scan a target
function Scan-Target {
  param([string]$Target, $Cfg, [string[]]$Engines)
  $name = Split-Path $Target -Leaf
  $stamp = (Get-Random)
  $safe = ($name -replace '[^\w\.-]','_')
  $results = @()
  $scanRoot = $Target
  $temp = $null

  if ((Test-Path $Target -PathType Leaf) -and ($ArchiveExt -contains ([IO.Path]::GetExtension($Target).ToLower()))) {
    Sec "ARCHIVE: $name"
    # list >2GiB members (ClamAV can't scan those)
    if ($Cfg.tools.sevenZip) {
      $list = & $Cfg.tools.sevenZip l $Target 2>$null
      $big = $list | Where-Object { $_ -match '^\d{4}-\d{2}-\d{2}' } |
        ForEach-Object {
          $c = ($_ -split '\s+'); if ($c.Count -ge 5 -and $c[3] -match '^\d+$' -and [int64]$c[3] -gt 2147483647) {
            '{0,7:N1} GiB  {1}' -f ([int64]$c[3]/1GB), ($c[5..($c.Count-1)] -join ' ')
          }
        }
      if ($big) { Warn 'Files >2 GiB (ClamAV cannot scan these):'; $big | ForEach-Object { Info "    $_" } }
    }
    $temp = Join-Path ([IO.Path]::GetTempPath()) "scanav_$stamp"
    Info 'Extracting...'
    Extract-Surface -Archive $Target -Dest $temp -Cfg $Cfg
    $n = @(Get-ChildItem $temp -Recurse -File -ErrorAction SilentlyContinue).Count
    Info "Extracted $n file(s) to scan."
    if ($n -eq 0) { Info '(nothing to scan)'; Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue; return }
    $scanRoot = $temp
  } elseif (Test-Path $Target -PathType Container) {
    Sec "FOLDER: $Target"
  } else {
    Bad "Not found or unsupported: $Target"; return
  }

  foreach ($eng in $Engines) {
    $log = Join-Path $LogDir ("{0}_{1}_{2}.log" -f $eng, $safe, $stamp)
    if ($eng -eq 'clamav') {
      Info 'Running ClamAV...'
      $r = Run-ClamAV -Target $scanRoot -Log $log -Cfg $Cfg
    } else {
      Info 'Running Emsisoft...'
      $r = Run-Emsisoft -Target $scanRoot -Log $log -Cfg $Cfg
    }
    $results += $r
    if ($r.Hits.Count -gt 0) {
      Bad ("{0}: {1} DETECTION(S)" -f $r.Engine, $r.Hits.Count)
      $r.Hits | ForEach-Object { Bad "    $_" }
    } else {
      $sk = if ($r.Skipped) { " ($($r.Skipped) skipped >limit)" } else { '' }
      Ok ("{0}: clean - scanned {1} file(s){2}" -f $r.Engine, $r.Scanned, $sk)
    }
    Info "    log: $log"
  }

  if ($temp) { Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue }

  $totalHits = 0; foreach ($r in $results) { $totalHits += $r.Hits.Count }
  Write-Host ''
  if ($totalHits -gt 0) {
    Bad "==> THREAT(S) FOUND in $name. If only ONE engine flagged it, verify the file's SHA-256 on VirusTotal before acting (could be a packer/Denuvo false positive)."
  } else {
    Ok "==> CLEAN: $name"
  }
  return [pscustomobject]@{ Target=$name; Hits=$totalHits; Results=$results }
}

# ================================================================ MAIN
if ($Install)        { Invoke-Install; return }
if ($InstallEngines) { Install-Engines; return }
if ($Configure)      { Invoke-Configure | Out-Null; return }

$cfg = Load-Config
if (-not $cfg) { Warn 'No config found - running first-run setup.'; $cfg = Invoke-Configure; if (-not $cfg) { return } }

# which engines this run
$engines = @()
$want = if ($Engine -eq 'config') { @{clamav=$cfg.engines.clamav; emsisoft=$cfg.engines.emsisoft} }
        elseif ($Engine -eq 'both') { @{clamav=$true; emsisoft=$true} }
        else { @{clamav=($Engine -eq 'clamav'); emsisoft=($Engine -eq 'emsisoft')} }
if ($want.clamav   -and $cfg.tools.clamscan) { $engines += 'clamav' }
if ($want.emsisoft -and $cfg.tools.a2cmd)    { $engines += 'emsisoft' }
if (-not $engines) { Bad 'No usable engine for this run (check config / -Engine).'; return }
if ($Full) { $cfg.options.mode = 'full' }

# definition updates
if ($Update) {
  Sec 'Updating virus definitions'
  if (($engines -contains 'clamav') -and $cfg.tools.freshclam) {
    Info 'freshclam...'; try { & $cfg.tools.freshclam *> (Join-Path $LogDir 'freshclam.log'); Ok 'ClamAV defs updated.' } catch { Warn "freshclam failed: $_" }
  }
  if (($engines -contains 'emsisoft') -and $cfg.tools.a2cmd) {
    Info 'a2cmd /update...'; try { & $cfg.tools.a2cmd '/update' *> (Join-Path $LogDir 'a2update.log'); Ok 'Emsisoft defs updated.' } catch { Warn "a2cmd update failed: $_" }
  }
}

# targets
$targets = if ($Path) { $Path } else { $cfg.scanFolders }
if (-not $targets) { Warn 'Nothing to scan. Pass -Path <file/folder> or add folders via -Configure.'; return }

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Sec ("scan-av  -  engines: {0}   mode: {1}   targets: {2}" -f ($engines -join '+'), $cfg.options.mode, @($targets).Count)

$all = @()
foreach ($t in $targets) { $all += (Scan-Target -Target $t -Cfg $cfg -Engines $engines) }

# final summary
Write-Host ''
Sec 'SUMMARY'
$threats = @($all | Where-Object { $_.Hits -gt 0 })
foreach ($r in $all) {
  if ($r.Hits -gt 0) { Bad ("  THREAT  {0}  ({1} hit(s))" -f $r.Target, $r.Hits) }
  else               { Ok  ("  clean   {0}" -f $r.Target) }
}
Write-Host ''
if ($threats) { Bad ("{0} of {1} target(s) flagged. Review logs in $LogDir and verify on VirusTotal." -f $threats.Count, $all.Count) }
else          { Ok  ("All {0} target(s) clean." -f $all.Count) }
