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
  [switch]$Shortcut,
  [switch]$NoPromptShortcut,
  [string[]]$Path,
  [switch]$Full,
  [ValidateSet('clamav','emsisoft','both','config')] [string]$Engine = 'config',
  [switch]$Update,
  [switch]$NoUpdate,
  [switch]$NoElevate,
  [switch]$RescanAll,
  [switch]$NoIncremental,
  [string[]]$AddFolder,
  [string[]]$RemoveFolder,
  [switch]$ListFolders,
  [switch]$Gui,
  [switch]$SelfUpdate,
  [switch]$InstallContextMenu,
  [switch]$RemoveContextMenu,
  [switch]$Help
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- paths / dirs
$AppDir  = Join-Path $env:LOCALAPPDATA 'ScanAV'
$CfgFile = Join-Path $AppDir 'config.json'
$LogDir  = Join-Path $AppDir 'logs'
$EngDir  = Join-Path $AppDir 'engines'
$CacheFile = Join-Path $AppDir 'scan-cache.json'
$script:LiveScan = $false   # set true by -Verbose: stream engine output live to console
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

# ---------------------------------------------------------------- elevation
function Test-IsAdmin {
  try { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) }
  catch { $false }
}

# Relaunch this script elevated, forwarding the original parameters, so Emsisoft's
# a2cmd runs inline (no separate self-elevation window mid-scan). Returns $true if a
# new elevated process was started (caller should then exit).
function Invoke-RelaunchElevated {
  param([hashtable]$Bound)
  if (-not $PSCommandPath) { return $false }   # can't relaunch a -Command invocation
  $a = @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File', "`"$PSCommandPath`"")
  foreach ($k in $Bound.Keys) {
    if ($k -eq 'NoElevate') { continue }
    $v = $Bound[$k]
    if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $a += "-$k" } }
    elseif ($v -is [array]) { $a += "-$k"; $a += (($v | ForEach-Object { '"' + $_ + '"' }) -join ',') }
    else { $a += "-$k"; $a += ('"' + $v + '"') }
  }
  try {
    $hostExe = (Get-Process -Id $PID).Path   # the powershell.exe running us
    Start-Process -FilePath $hostExe -Verb RunAs -ArgumentList $a -ErrorAction Stop
    return $true
  } catch { Warn "Elevation cancelled/failed: $_"; return $false }
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
  $autoUpd  = AskYesNo '  Auto-update virus definitions before scanning?' $true
  $incr     = AskYesNo '  Skip files already scanned & unchanged (incremental)?' $true

  $cfg = [ordered]@{
    version   = 1
    tools     = [ordered]@{ sevenZip=$sevenZ; clamscan=$clam; freshclam=$fresh; a2cmd=$a2 }
    engines   = [ordered]@{ clamav=$useClam; emsisoft=$useEms }
    scanFolders = $folders
    options   = [ordered]@{
      mode='exec'; maxFileSizeMB=$maxFile; maxScanSizeMB=$maxScan
      execExtensions=$DefaultExecExt; tempDir=''
      autoUpdate=$autoUpd; updateMaxAgeHours=12; autoElevate=$true; incremental=$incr
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
    $frc = Invoke-Native -Exe $fresh -Arguments @("--config-file=$fcConf", "--datadir=$dbDir") -Log (Join-Path $LogDir 'freshclam_install.log')
    if ($frc -eq 0) { Ok '  definitions updated.' } else { Warn "  freshclam exit $frc (see logs\freshclam_install.log; you can run it later)." }
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
  if ($SevenZip) { $null = Invoke-Native -Exe $SevenZip -Arguments @('x', $sfx, "-o$dest", '-y'); if (Test-Path $dest) { $extracted = $true } }
  if (-not $extracted) {
    Warn '  Could not silently extract (7-Zip needed). Launching the EEK extractor - accept the default folder, then re-run: scan-av -Configure'
    Start-Process $sfx; return $null
  }
  $a2 = Get-ChildItem $dest -Recurse -Filter 'a2cmd.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $a2) { Warn '  a2cmd.exe not found after extraction; run the EEK GUI once, then: scan-av -Configure'; return $null }
  Ok "  installed: $($a2.FullName)"
  Info '  updating Emsisoft definitions (large first-time download)...'
  $urc = Invoke-Native -Exe $a2.FullName -Arguments @('/update') -Log (Join-Path $LogDir 'a2update_install.log')
  if ($urc -eq 0) { Ok '  definitions updated.' } else { Warn "  a2cmd /update exit $urc (run later)." }
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

# ---------------------------------------------------------------- desktop shortcut
# Plain desktop shortcut that runs scan-av. -Elevated marks it "Run as administrator"
# so Emsisoft's a2cmd (which self-elevates) doesn't pop a separate UAC/cmd window on
# every run -- you approve once at launch instead of once per scan/archive.
function New-DesktopShortcut {
  param([bool]$Elevated = $true)
  $ps1 = Join-Path $AppDir 'scan-av.ps1'
  if (-not (Test-Path $ps1)) { Warn "scan-av.ps1 not found in $AppDir - run -Install first."; return }
  try {
    $lnkPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Scan-AV.lnk'
    $ws  = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath       = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    # launch the GUI app (hidden console host + the window)
    $lnk.Arguments        = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ps1`" -Gui"
    $lnk.WorkingDirectory = $AppDir
    $lnk.Description       = 'Open the scan-av app'
    $lnk.IconLocation     = 'imageres.dll,79'
    $lnk.Save()
    if ($Elevated) {
      # set the "Run as administrator" bit (byte 0x15, flag 0x20) in the .lnk
      $b = [IO.File]::ReadAllBytes($lnkPath); $b[0x15] = $b[0x15] -bor 0x20
      [IO.File]::WriteAllBytes($lnkPath, $b)
    }
    Ok "Desktop shortcut created: $lnkPath"
    if ($Elevated) { Info 'It runs elevated -> one UAC prompt at launch, no per-scan Emsisoft prompts.' }
  } catch { Warn "Could not create desktop shortcut: $_" }
}

# Zero-prompt option: an elevated Scheduled Task (RunLevel Highest) plus a desktop
# shortcut that triggers it. Registering the task needs admin ONCE; after that the
# task -- and therefore a2cmd -- runs elevated with no UAC prompt at all.
function Register-NoPromptTask {
  $ps1 = Join-Path $AppDir 'scan-av.ps1'
  if (-not (Test-Path $ps1)) { Warn "scan-av.ps1 not found in $AppDir - run -Install first."; return }
  try {
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoExit -ExecutionPolicy Bypass -File `"$ps1`""
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName 'ScanAV' -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
    Ok "Elevated scheduled task 'ScanAV' registered (no UAC prompt when run)."
    $lnkPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Scan-AV.lnk'
    $ws  = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath   = Join-Path $env:SystemRoot 'System32\schtasks.exe'
    $lnk.Arguments    = '/run /tn ScanAV'
    $lnk.IconLocation = 'imageres.dll,79'
    $lnk.Description  = 'Run scan-av (elevated, no prompt)'
    $lnk.Save()
    Ok "Desktop shortcut now triggers the task (zero prompts): $lnkPath"
  } catch {
    Warn "Could not register the elevated task: $_"
    Warn 'Run PowerShell **as Administrator** once, then: scan-av -NoPromptShortcut'
  }
}

# ---------------------------------------------------------------- explorer menu
# Adds a per-user (HKCU, no admin) "Antivirus Scan" entry to the folder right-click
# menu. Selecting a folder and clicking it scans just that folder. On Windows 11 it
# appears under "Show more options".
function Install-ContextMenu {
  $ps1 = Join-Path $AppDir 'scan-av.ps1'
  if (-not (Test-Path $ps1)) { Warn "scan-av.ps1 not found in $AppDir - run -Install first."; return }
  $pw = Join-Path $PSHOME 'powershell.exe'
  $verb = 'AntivirusScan'; $label = 'Antivirus Scan'
  $cmdSel = '"{0}" -NoProfile -ExecutionPolicy Bypass -NoExit -Command "& ''{1}'' -Path ''%1'' -RescanAll -Verbose"' -f $pw, $ps1
  $cmdBg  = '"{0}" -NoProfile -ExecutionPolicy Bypass -NoExit -Command "& ''{1}'' -Path ''%V'' -RescanAll -Verbose"' -f $pw, $ps1
  $targets = @(
    @{ root = "HKCU:\Software\Classes\Directory\shell\$verb";            cmd = $cmdSel },  # folder selected
    @{ root = "HKCU:\Software\Classes\Directory\Background\shell\$verb";  cmd = $cmdBg  }   # inside a folder
  )
  foreach ($t in $targets) {
    try {
      New-Item -Path $t.root -Force | Out-Null
      Set-ItemProperty -Path $t.root -Name '(Default)' -Value $label
      Set-ItemProperty -Path $t.root -Name 'Icon' -Value $pw
      New-Item -Path "$($t.root)\command" -Force | Out-Null
      Set-ItemProperty -Path "$($t.root)\command" -Name '(Default)' -Value $t.cmd
    } catch { Warn "  context-menu registry write failed: $_" }
  }
  Ok "Added 'Antivirus Scan' to the folder right-click menu."
  Info "On Windows 11 it's under 'Show more options' (Shift+F10 shows it directly)."
}
function Remove-ContextMenu {
  foreach ($r in @("HKCU:\Software\Classes\Directory\shell\AntivirusScan","HKCU:\Software\Classes\Directory\Background\shell\AntivirusScan")) {
    if (Test-Path $r) { Remove-Item $r -Recurse -Force -ErrorAction SilentlyContinue }
  }
  Ok "Removed the 'Antivirus Scan' right-click menu entry."
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
  # desktop shortcut (elevated, so Emsisoft doesn't prompt per scan)
  New-DesktopShortcut -Elevated $true
  Info "For ZERO UAC prompts, run PowerShell as Admin once: scan-av -NoPromptShortcut"
  Write-Host ''
  if (AskYesNo "Add 'Antivirus Scan' to the folder right-click menu?" $true) { Install-ContextMenu }
  Write-Host ''
  if ($WithEngines -or (AskYesNo 'Auto-download & install ClamAV + Emsisoft now?' $true)) {
    Install-Engines
  } else {
    Invoke-Configure | Out-Null
  }
}

# ---------------------------------------------------------------- engines
# Run a native exe WITHOUT letting its stderr abort the script. With
# $ErrorActionPreference='Stop', PowerShell turns any native-command stderr line
# (e.g. clamscan's skippable "Can't fstat descriptor" warnings) into a terminating
# NativeCommandError. We localize EAP=Continue and capture all streams to a log.
function Invoke-Native {
  # $Live = $true streams output to the console (Tee-Object) AND logs it; otherwise
  # output is captured silently to $Log. Out-Host consumes the pipeline so the streamed
  # lines never leak into the function's return value ($LASTEXITCODE).
  param([Parameter(Mandatory)][string]$Exe, [string[]]$Arguments = @(), [string]$Log, [bool]$Live = $false)
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    # Stringify the merged stream so native stderr shows as plain text instead of
    # red PowerShell NativeCommandError blocks (clamscan's per-file "Can't fstat"
    # warnings are not fatal and shouldn't look like a script error).
    if ($Live -and $Log) { & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $Log | Out-Host }
    elseif ($Live)       { & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Out-Host }
    elseif ($Log)        { & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Out-File -FilePath $Log -Encoding UTF8 }
    else                 { & $Exe @Arguments 2>&1 | Out-Null }
  } catch { if ($Log) { "scan-av: native call raised: $_" | Out-File -FilePath $Log -Append -Encoding UTF8 } }
  finally { $ErrorActionPreference = $prev }
  return $LASTEXITCODE
}

function Run-ClamAV {
  param([string]$Target, [string]$Log, $Cfg)
  $a = @('-r', "--max-filesize=$($Cfg.options.maxFileSizeMB)M",
              "--max-scansize=$($Cfg.options.maxScanSizeMB)M",
              '--alert-exceeds-max=yes', $Target)
  $rc = Invoke-Native -Exe $Cfg.tools.clamscan -Arguments $a -Log $Log -Live $script:LiveScan
  $lines = Get-Content $Log -ErrorAction SilentlyContinue
  $hits  = @($lines | Where-Object { $_ -match ' FOUND$' -and $_ -notmatch 'Heuristics\.Limits\.Exceeded' })
  $skips = @($lines | Where-Object { $_ -match 'Heuristics\.Limits\.Exceeded' })
  [pscustomobject]@{ Engine='ClamAV'; Rc=$rc; Hits=$hits; Skipped=$skips.Count
    Scanned = ([regex]::Match(($lines -join "`n"),'Scanned files:\s*(\d+)').Groups[1].Value) }
}

# a2cmd needs its path values quoted as /f="path". PowerShell's native-argument
# passing won't reliably produce that for spaced paths (the value gets split and
# a2cmd reports "no objects to scan"). Invoke it through ProcessStartInfo with an
# explicit, correctly-quoted command line instead. Also avoids the stderr issue.
function Invoke-A2cmd {
  param([string]$Exe, [string]$Target, [string]$Log, [bool]$Live = $false)
  $argStr = '/f="{0}" /s /a /pup /log="{1}" /loglevel=detailed' -f $Target, $Log
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  $psi.Arguments = $argStr
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $console = Join-Path $LogDir '_a2cmd_console.txt'
  try { $p = [System.Diagnostics.Process]::Start($psi) }
  catch { "scan-av: failed to start a2cmd: $_" | Out-File $console -Encoding UTF8; return 999 }
  $outT = $p.StandardOutput.ReadToEndAsync()   # async read avoids stdout/stderr deadlock
  $errT = $p.StandardError.ReadToEndAsync()
  $p.WaitForExit()
  $txt = ($outT.Result + "`r`n" + $errT.Result)
  $txt | Out-File -FilePath $console -Encoding UTF8
  if ($Live) { Write-Host $txt }
  return $p.ExitCode
}

function Run-Emsisoft {
  param([string]$Target, [string]$Log, $Cfg)
  $rc = Invoke-A2cmd -Exe $Cfg.tools.a2cmd -Target $Target -Log $Log -Live $script:LiveScan
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
    $null = Invoke-Native -Exe $Cfg.tools.sevenZip -Arguments @('x', $Archive, "-o$Dest", '-y')
  } else {
    $inc = $Cfg.options.execExtensions | ForEach-Object { "-ir!*.$_" }
    $null = Invoke-Native -Exe $Cfg.tools.sevenZip -Arguments (@('x', $Archive, "-o$Dest") + $inc + @('-y'))
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
      $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
      $list = & $Cfg.tools.sevenZip l $Target 2>$null
      $ErrorActionPreference = $prevEAP
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
  } elseif (Test-Path $Target -PathType Leaf) {
    Sec "FILE: $name"   # a single loose file -> scan it directly
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
    } elseif (-not $r.Scanned -or $r.Scanned -eq '0') {
      # no summary / 0 files = the engine errored or had nothing to scan, NOT a clean result
      Warn ("{0}: no result (exit {1}) - it errored or found nothing to scan. See log." -f $r.Engine, $r.Rc)
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

# ---------------------------------------------------------------- definitions
function Update-Definitions {
  param($Cfg, [string[]]$Engines)
  Sec 'Updating virus definitions'
  $ok = $true
  if (($Engines -contains 'clamav') -and $Cfg.tools.freshclam) {
    Info 'freshclam...'
    $fcDir = Split-Path $Cfg.tools.freshclam
    $fa = @()
    $conf = Join-Path $fcDir 'freshclam.conf'; if (Test-Path $conf) { $fa += "--config-file=$conf" }
    $db   = Join-Path $fcDir 'database';       if (Test-Path $db)   { $fa += "--datadir=$db" }
    $rc = Invoke-Native -Exe $Cfg.tools.freshclam -Arguments $fa -Log (Join-Path $LogDir 'freshclam.log')
    if ($rc -eq 0) { Ok 'ClamAV definitions up to date.' } else { Warn "freshclam exit $rc (see logs\freshclam.log)"; $ok = $false }
  }
  if (($Engines -contains 'emsisoft') -and $Cfg.tools.a2cmd) {
    Info 'a2cmd /update...'
    $rc = Invoke-Native -Exe $Cfg.tools.a2cmd -Arguments @('/update') -Log (Join-Path $LogDir 'a2update.log')
    if ($rc -eq 0) { Ok 'Emsisoft definitions up to date.' } else { Warn "a2cmd /update exit $rc (see logs\a2update.log)"; $ok = $false }
  }
  if ($ok) { Set-Content -Path (Join-Path $AppDir 'last-update.txt') -Value ([DateTime]::UtcNow.ToString('o')) -Encoding ASCII }
  return $ok
}

# ---------------------------------------------------------------- self-update
$RawUrl = 'https://raw.githubusercontent.com/dggomes/avscan/main/windows/scan-av.ps1'
# Download the latest scan-av.ps1 from GitHub, validate it (non-trivial + parses),
# back up the current copy, and replace the installed file. Returns {ok,msg}.
function Update-FromGitHub {
  $dst = Join-Path $AppDir 'scan-av.ps1'
  $tmp = Join-Path $env:TEMP ('scanav_update_' + [Guid]::NewGuid().ToString('N') + '.ps1')
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $RawUrl -OutFile $tmp -UseBasicParsing -Headers @{ 'Cache-Control' = 'no-cache' } -ErrorAction Stop
  } catch { return [pscustomobject]@{ ok = $false; msg = "Download failed: $_" } }
  $content = Get-Content $tmp -Raw -ErrorAction SilentlyContinue
  if (-not $content -or $content.Length -lt 5000 -or $content -notmatch 'function Show-Gui') {
    return [pscustomobject]@{ ok = $false; msg = 'Downloaded file looks invalid; not applied.' }
  }
  $perr = $null
  [void][System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$perr)
  if ($perr -and $perr.Count) { return [pscustomobject]@{ ok = $false; msg = 'Downloaded file has parse errors; not applied.' } }
  try {
    if (Test-Path $dst) { Copy-Item $dst "$dst.bak" -Force }
    Copy-Item $tmp $dst -Force
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ ok = $true; msg = 'Updated to the latest version from GitHub. Restart to use it.' }
  } catch { return [pscustomobject]@{ ok = $false; msg = "Could not replace installed file: $_" } }
}

# ---------------------------------------------------------------- GUI
# A WinForms app: pick folders (and sub-folders) to scan, add/remove them, update
# definitions, view logs, and self-update from GitHub. Scanning is handed to the
# console engine (a new powershell window) so the UI never freezes.
# ================================================================ GUI helpers
# Script-scoped so WPF event handlers can call them reliably regardless of closure
# scope. Per-card handlers read the node from the element's .Tag (no closures).
function script:WBrush([string]$hex) { (New-Object System.Windows.Media.BrushConverter).ConvertFromString($hex) }

function script:New-ModelNode([string]$path, [bool]$isFolder, [int]$depth) {
  $hasKids = $false
  if ($isFolder) { try { $hasKids = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue | Select-Object -First 1).Count -gt 0 } catch {} }
  [pscustomobject]@{ Path=$path; Name=(Split-Path $path -Leaf); IsFolder=$isFolder; HasChildren=$hasKids; Expanded=$false; Checked=$false; Loaded=$false; Children=@(); Depth=$depth }
}
function script:Load-ModelChildren($node) {
  if ($node.Loaded) { return }
  $kids = @()
  try {
    Get-ChildItem -LiteralPath $node.Path -Force -ErrorAction SilentlyContinue | Sort-Object @{e={-not $_.PSIsContainer}}, Name | ForEach-Object {
      $kids += (New-ModelNode $_.FullName ([bool]$_.PSIsContainer) ($node.Depth + 1))
    }
  } catch {}
  $node.Children = $kids; $node.Loaded = $true
}
function script:New-TargetCard($node) {
  $card = New-Object System.Windows.Controls.Border
  $card.Background = (WBrush '#10141E'); $card.CornerRadius = New-Object System.Windows.CornerRadius 14
  $card.BorderBrush = (WBrush '#1A2130'); $card.BorderThickness = New-Object System.Windows.Thickness 1
  $card.Margin = New-Object System.Windows.Thickness (($node.Depth * 26),0,0,8)
  $card.Padding = New-Object System.Windows.Thickness 14,10,14,10
  $card.MinHeight = 62; $card.Cursor = [System.Windows.Input.Cursors]::Hand; $card.Tag = $node

  $g = New-Object System.Windows.Controls.Grid
  $gAuto = [System.Windows.GridLength]::Auto
  $gStar = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
  $c0 = New-Object System.Windows.Controls.ColumnDefinition; $c0.Width = $gAuto
  $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = $gStar
  $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = $gAuto
  $g.ColumnDefinitions.Add($c0); $g.ColumnDefinitions.Add($c1); $g.ColumnDefinitions.Add($c2)

  $chip = New-Object System.Windows.Controls.Border
  $chip.Width = 40; $chip.Height = 40; $chip.CornerRadius = New-Object System.Windows.CornerRadius 10
  $chip.Background = (WBrush '#1A2231'); $chip.Margin = New-Object System.Windows.Thickness 0,0,14,0
  $gl = New-Object System.Windows.Controls.TextBlock
  $gl.Text = [string]$(if ($node.IsFolder) { [char]0xE8B7 } else { [char]0xE8A5 })
  $gl.FontFamily = New-Object System.Windows.Media.FontFamily 'Segoe MDL2 Assets'
  $gl.FontSize = 18; $gl.Foreground = (WBrush '#9AA6BC'); $gl.HorizontalAlignment = 'Center'; $gl.VerticalAlignment = 'Center'
  $chip.Child = $gl
  [System.Windows.Controls.Grid]::SetColumn($chip,0); [void]$g.Children.Add($chip)

  $sp = New-Object System.Windows.Controls.StackPanel; $sp.VerticalAlignment = 'Center'
  $t1 = New-Object System.Windows.Controls.TextBlock; $t1.Text = $node.Name; $t1.FontSize = 16; $t1.Foreground = (WBrush '#FFFFFF'); $t1.TextTrimming = 'CharacterEllipsis'
  $sub = if ($node.IsFolder) { if ($node.Loaded) { "{0} items" -f $node.Children.Count } else { 'Folder' } } else { 'File' }
  $t2 = New-Object System.Windows.Controls.TextBlock; $t2.Text = $sub; $t2.FontSize = 12; $t2.Foreground = (WBrush '#8A93A6'); $t2.Margin = New-Object System.Windows.Thickness 0,2,0,0
  [void]$sp.Children.Add($t1); [void]$sp.Children.Add($t2)
  [System.Windows.Controls.Grid]::SetColumn($sp,1); [void]$g.Children.Add($sp)

  $tr = New-Object System.Windows.Controls.StackPanel; $tr.Orientation = 'Horizontal'; $tr.VerticalAlignment = 'Center'
  if ($node.IsFolder -and $node.HasChildren) {
    $chev = New-Object System.Windows.Controls.TextBlock
    $chev.Text = [string]$(if ($node.Expanded) { [char]0xE70E } else { [char]0xE70D })
    $chev.FontFamily = New-Object System.Windows.Media.FontFamily 'Segoe MDL2 Assets'
    $chev.FontSize = 16; $chev.Foreground = (WBrush '#8A93A6'); $chev.Margin = New-Object System.Windows.Thickness 0,0,14,0; $chev.VerticalAlignment = 'Center'
    [void]$tr.Children.Add($chev)
  }
  $box = New-Object System.Windows.Controls.Border
  $box.Width = 34; $box.Height = 34; $box.CornerRadius = New-Object System.Windows.CornerRadius 9; $box.VerticalAlignment = 'Center'; $box.Tag = $node
  if ($node.Checked) {
    $box.Background = (WBrush '#6D5BF0'); $box.BorderThickness = New-Object System.Windows.Thickness 0
    $ck = New-Object System.Windows.Controls.TextBlock; $ck.Text = [string][char]0xE73E; $ck.FontFamily = New-Object System.Windows.Media.FontFamily 'Segoe MDL2 Assets'; $ck.FontSize = 16; $ck.Foreground = (WBrush '#FFFFFF'); $ck.HorizontalAlignment='Center'; $ck.VerticalAlignment='Center'
    $box.Child = $ck
  } else {
    $box.Background = (WBrush '#0C1018'); $box.BorderBrush = (WBrush '#39414F'); $box.BorderThickness = New-Object System.Windows.Thickness 2
  }
  [void]$tr.Children.Add($box)
  [System.Windows.Controls.Grid]::SetColumn($tr,2); [void]$g.Children.Add($tr)
  $card.Child = $g

  $box.Add_MouseLeftButtonUp({ param($s,$e) $n = $s.Tag; $n.Checked = -not $n.Checked; $e.Handled = $true; Render-Targets })
  $card.Add_MouseLeftButtonUp({
    param($s,$e)
    $n = $s.Tag
    if ($n.IsFolder -and $n.HasChildren) {
      if (-not $n.Expanded -and -not $n.Loaded) { Load-ModelChildren $n }
      $n.Expanded = -not $n.Expanded
    } else { $n.Checked = -not $n.Checked }
    Render-Targets
  })
  return $card
}
function script:Emit-Node($node) {
  [void]$script:TargetsPanel.Children.Add((New-TargetCard $node))
  if ($node.Expanded) { foreach ($c in $node.Children) { Emit-Node $c } }
}
function script:Render-Targets {
  if (-not $script:TargetsPanel) { return }
  $script:TargetsPanel.Children.Clear()
  foreach ($n in $script:rootNodes) { Emit-Node $n }
}
function script:Rebuild-Roots {
  $script:rootNodes = @()
  foreach ($f in @($script:guiCfg.scanFolders)) {
    if (Test-Path $f) { $n = New-ModelNode $f $true 0; $n.Checked = $true; $script:rootNodes += $n }
  }
  Render-Targets
}
function script:Collect-Targets {
  $acc = New-Object System.Collections.Generic.List[string]
  function walk($n) { if ($n.Checked) { $acc.Add([string]$n.Path) }; foreach ($c in $n.Children) { walk $c } }
  foreach ($n in $script:rootNodes) { walk $n }
  $set = @($acc | Select-Object -Unique); $tops = @()
  foreach ($p in $set) {
    $cov = $false
    foreach ($q in $set) { if ($q -ne $p -and $p.StartsWith($q + '\')) { $cov = $true; break } }
    if (-not $cov) { $tops += $p }
  }
  ,$tops
}
function script:Save-GuiCfg { ($script:guiCfg | ConvertTo-Json -Depth 6) | Set-Content -Path $CfgFile -Encoding UTF8 }

# ---- in-app run: launch a scan-av operation hidden and stream its output to the
# run panel (no separate console). Output is redirected to a temp file that a
# DispatcherTimer (UI thread) tails - avoids cross-thread UI updates.
$script:runTick = {
  try {
    if ($script:runOutFile -and (Test-Path $script:runOutFile)) {
      $fs = [System.IO.File]::Open($script:runOutFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
      [void]$fs.Seek($script:runPos, [System.IO.SeekOrigin]::Begin)
      $sr = New-Object System.IO.StreamReader($fs)
      $new = $sr.ReadToEnd(); $script:runPos = $fs.Position; $sr.Close(); $fs.Close()
      if ($new) { $script:runBox.AppendText($new); $script:runBox.ScrollToEnd() }
    }
  } catch {}
  if ($script:runProc -and $script:runProc.HasExited) {
    if ($script:runTimer) { $script:runTimer.Stop() }
    $script:runProc = $null
    $script:runProgress.IsIndeterminate = $false; $script:runProgress.Visibility = 'Collapsed'
    $script:runTitle.Text = 'Done'
    $script:runBack.Content = 'Back to Dashboard'
    if ($script:runCancel) { $script:runCancel.Visibility = 'Collapsed' }
  }
}
function script:Stop-InAppRun {
  if ($script:runProc -and -not $script:runProc.HasExited) {
    try { Start-Process taskkill -ArgumentList "/PID $($script:runProc.Id) /T /F" -WindowStyle Hidden -Wait } catch {}
  }
  if ($script:runTimer) { $script:runTimer.Stop() }
  $script:runProc = $null
  $script:runProgress.IsIndeterminate = $false; $script:runProgress.Visibility = 'Collapsed'
  $script:runTitle.Text = 'Cancelled'
  $script:runBack.Content = 'Back to Dashboard'
  if ($script:runCancel) { $script:runCancel.Visibility = 'Collapsed' }
  if ($script:runBox) { $script:runBox.AppendText("`r`n--- cancelled by user ---`r`n"); $script:runBox.ScrollToEnd() }
}
function script:Start-InAppRun([string]$title, [string]$paramExpr) {
  $tmp = Join-Path $env:TEMP ('scanav_run_' + [Guid]::NewGuid().ToString('N') + '.log')
  Set-Content -Path $tmp -Value '' -Encoding UTF8
  $script:runOutFile = $tmp; $script:runPos = 0
  $script:runTitle.Text = $title
  $script:runBox.Text = ''
  if ($script:logListBorder) { $script:logListBorder.Visibility = 'Collapsed'; $script:logListCol.Width = New-Object System.Windows.GridLength(0) }
  $script:runProgress.IsIndeterminate = $true; $script:runProgress.Visibility = 'Visible'
  $script:runBack.Content = 'Hide'
  if ($script:runCancel) { $script:runCancel.Visibility = 'Visible' }
  $script:runView.Visibility = 'Visible'
  $ps1q = $script:guiPs1 -replace "'", "''"; $tmpq = $tmp -replace "'", "''"
  $cmd = "& '$ps1q' $paramExpr -NoElevate -Verbose *>&1 | Out-File -LiteralPath '$tmpq' -Encoding utf8"
  $psArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$cmd`""
  try { $script:runProc = Start-Process powershell.exe -ArgumentList $psArgs -WindowStyle Hidden -PassThru }
  catch { $script:runProc = $null; $script:runBox.AppendText("Failed to start: $_") }
  if (-not $script:runTimer) {
    $script:runTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:runTimer.Interval = [TimeSpan]::FromMilliseconds(400)
    $script:runTimer.add_Tick($script:runTick)
  }
  $script:runTimer.Start()
}
function script:Load-LogIntoBox([string]$path) {
  try { $script:runBox.Text = (Get-Content -LiteralPath $path -Raw -ErrorAction Stop) } catch { $script:runBox.Text = "Could not read log: $_" }
  $script:runTitle.Text = "Log: " + (Split-Path $path -Leaf)
  $script:runBox.ScrollToHome()
}
function script:New-LogButton($file) {
  $b = New-Object System.Windows.Controls.Border
  $b.Background = (WBrush '#10141E'); $b.CornerRadius = New-Object System.Windows.CornerRadius 10
  $b.BorderBrush = (WBrush '#1A2130'); $b.BorderThickness = New-Object System.Windows.Thickness 1
  $b.Margin = New-Object System.Windows.Thickness 0,0,0,8; $b.Padding = New-Object System.Windows.Thickness 12,8,12,8
  $b.Cursor = [System.Windows.Input.Cursors]::Hand; $b.Tag = $file.FullName
  $sp = New-Object System.Windows.Controls.StackPanel
  $n = New-Object System.Windows.Controls.TextBlock; $n.Text = $file.Name; $n.FontSize = 13; $n.Foreground = (WBrush '#E7ECF3'); $n.TextTrimming = 'CharacterEllipsis'
  $d = New-Object System.Windows.Controls.TextBlock; $d.Text = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + "   -   " + ('{0:N0} KB' -f ([math]::Max(1, $file.Length/1KB))); $d.FontSize = 11; $d.Foreground = (WBrush '#8A93A6'); $d.Margin = New-Object System.Windows.Thickness 0,2,0,0
  [void]$sp.Children.Add($n); [void]$sp.Children.Add($d); $b.Child = $sp
  $b.Add_MouseLeftButtonUp({ param($s,$e) Load-LogIntoBox ([string]$s.Tag) })
  return $b
}
function script:Show-LogsInApp {
  $script:runTitle.Text = 'Logs'
  $script:runProgress.Visibility = 'Collapsed'
  $script:runBack.Content = 'Back to Dashboard'
  if ($script:runCancel) { $script:runCancel.Visibility = 'Collapsed' }
  $script:logListBorder.Visibility = 'Visible'
  $script:logListCol.Width = New-Object System.Windows.GridLength(300)
  $script:logList.Children.Clear()
  $files = @(Get-ChildItem $LogDir -Filter *.log -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
  if (-not $files.Count) {
    $script:runBox.Text = 'No logs yet. Run a scan first.'
  } else {
    foreach ($f in $files) { [void]$script:logList.Children.Add((New-LogButton $f)) }
    Load-LogIntoBox $files[0].FullName
  }
  $script:runView.Visibility = 'Visible'
}

# ================================================================ GUI window
function Show-Gui {
  Add-Type -AssemblyName PresentationFramework
  Add-Type -AssemblyName PresentationCore
  Add-Type -AssemblyName WindowsBase
  Add-Type -AssemblyName System.Windows.Forms
  $cfg = Load-Config
  if (-not $cfg) {
    [System.Windows.Forms.MessageBox]::Show('No configuration found. Run "scan-av -Install" first.','scan-av') | Out-Null
    return
  }
  $script:guiCfg = $cfg
  $ps1 = if ($PSCommandPath) { $PSCommandPath } else { Join-Path $AppDir 'scan-av.ps1' }
  $script:guiPs1 = $ps1
  $incOn = if ($null -ne $cfg.options.incremental) { [bool]$cfg.options.incremental } else { $true }

  $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="scan-av" WindowState="Maximized" WindowStartupLocation="CenterScreen"
        Background="#070910" FontFamily="Segoe UI" Foreground="#FFFFFF">
  <Window.Resources>
    <Style x:Key="Nav" TargetType="Button">
      <Setter Property="Background" Value="Transparent"/><Setter Property="Foreground" Value="#AEB6C6"/>
      <Setter Property="Cursor" Value="Hand"/><Setter Property="Margin" Value="10,4"/><Setter Property="Height" Value="68"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="14" Padding="6"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#141A28"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Tile" TargetType="Button">
      <Setter Property="Background" Value="#11151F"/><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="18" Padding="14" BorderBrush="#1C2230" BorderThickness="1"><ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#19202E"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button">
      <Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" CornerRadius="16" Padding="22,14"><Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="1,1"><GradientStop Color="#6D5BF0" Offset="0"/><GradientStop Color="#8B5CF6" Offset="1"/></LinearGradientBrush></Border.Background><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.92"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Soft" TargetType="Button">
      <Setter Property="Background" Value="#11151F"/><Setter Property="Foreground" Value="#C7CEDA"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="12" Padding="14,8" BorderBrush="#222A38" BorderThickness="1"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#19202E"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.ColumnDefinitions><ColumnDefinition Width="104"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>

    <Border Grid.Column="0" Background="#0B0E16">
      <StackPanel Margin="0,18">
        <Border Width="56" Height="56" CornerRadius="16" Margin="0,0,0,18" HorizontalAlignment="Center"><Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="1,1"><GradientStop Color="#6D5BF0" Offset="0"/><GradientStop Color="#8B5CF6" Offset="1"/></LinearGradientBrush></Border.Background><TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" FontSize="24" Foreground="White" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <Button x:Name="NavDashboard" Style="{StaticResource Nav}"><StackPanel><TextBlock Text="&#xE80F;" FontFamily="Segoe MDL2 Assets" FontSize="22" HorizontalAlignment="Center"/><TextBlock Text="Dashboard" FontSize="12" Margin="0,4,0,0" HorizontalAlignment="Center"/></StackPanel></Button>
        <Button x:Name="NavScan" Style="{StaticResource Nav}"><StackPanel><TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" FontSize="22" HorizontalAlignment="Center"/><TextBlock Text="Scan" FontSize="12" Margin="0,4,0,0" HorizontalAlignment="Center"/></StackPanel></Button>
        <Button x:Name="NavProtection" Style="{StaticResource Nav}"><StackPanel><TextBlock Text="&#xE83D;" FontFamily="Segoe MDL2 Assets" FontSize="22" HorizontalAlignment="Center"/><TextBlock Text="Protection" FontSize="12" Margin="0,4,0,0" HorizontalAlignment="Center"/></StackPanel></Button>
        <Button x:Name="NavUpdates" Style="{StaticResource Nav}"><StackPanel><TextBlock Text="&#xE72C;" FontFamily="Segoe MDL2 Assets" FontSize="22" HorizontalAlignment="Center"/><TextBlock Text="Updates" FontSize="12" Margin="0,4,0,0" HorizontalAlignment="Center"/></StackPanel></Button>
        <Button x:Name="NavLogs" Style="{StaticResource Nav}"><StackPanel><TextBlock Text="&#xE8A5;" FontFamily="Segoe MDL2 Assets" FontSize="22" HorizontalAlignment="Center"/><TextBlock Text="Logs" FontSize="12" Margin="0,4,0,0" HorizontalAlignment="Center"/></StackPanel></Button>
        <Button x:Name="NavSettings" Style="{StaticResource Nav}"><StackPanel><TextBlock Text="&#xE713;" FontFamily="Segoe MDL2 Assets" FontSize="22" HorizontalAlignment="Center"/><TextBlock Text="Settings" FontSize="12" Margin="0,4,0,0" HorizontalAlignment="Center"/></StackPanel></Button>
        <Button x:Name="NavAbout" Style="{StaticResource Nav}"><StackPanel><TextBlock Text="&#xE946;" FontFamily="Segoe MDL2 Assets" FontSize="22" HorizontalAlignment="Center"/><TextBlock Text="About" FontSize="12" Margin="0,4,0,0" HorizontalAlignment="Center"/></StackPanel></Button>
      </StackPanel>
    </Border>

    <Grid Grid.Column="1" Margin="28,22,28,18">
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>

      <Grid Grid.Row="0" Margin="0,0,0,18">
        <StackPanel HorizontalAlignment="Left"><TextBlock Text="Antivirus Scan - Downloaded Files" FontSize="24" FontWeight="Bold"/><TextBlock x:Name="HeaderInfo" FontSize="14" Foreground="#8A93A6" Margin="0,4,0,0"/></StackPanel>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
          <Button x:Name="BtnSettings" Style="{StaticResource Soft}" Margin="0,0,10,0"><StackPanel Orientation="Horizontal"><TextBlock Text="&#xE713;" FontFamily="Segoe MDL2 Assets" FontSize="16" Margin="0,0,8,0"/><TextBlock Text="Settings" FontSize="15"/></StackPanel></Button>
          <Button x:Name="BtnMore" Style="{StaticResource Soft}"><TextBlock Text="&#xE712;" FontFamily="Segoe MDL2 Assets" FontSize="16"/></Button>
        </StackPanel>
      </Grid>

      <Border Grid.Row="1" CornerRadius="20" BorderBrush="#3A3580" BorderThickness="1.5" Margin="0,0,0,22">
        <Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="1,0"><GradientStop Color="#141233" Offset="0"/><GradientStop Color="#0A0F18" Offset="0.6"/></LinearGradientBrush></Border.Background>
        <Grid Margin="26,22">
          <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <Grid Grid.Column="0" Width="130" Height="130" Margin="0,0,28,0"><Ellipse Stroke="#6D5BF0" StrokeThickness="7"/><TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" FontSize="52" Foreground="#8B8BF8" HorizontalAlignment="Center" VerticalAlignment="Center"/></Grid>
          <StackPanel Grid.Column="1" VerticalAlignment="Center">
            <TextBlock x:Name="HeroHeadline" Text="Ready to scan" FontSize="32" FontWeight="Bold"/>
            <TextBlock x:Name="HeroSub" Text="On-demand malware scanner. Run a scan to check your games and downloads." FontSize="16" Foreground="#9BA3B4" Margin="0,6,0,0" TextWrapping="Wrap"/>
            <TextBlock x:Name="HeroLast" Text="Last scan: Never" FontSize="14" Foreground="#6B7280" Margin="0,12,0,0"/>
          </StackPanel>
          <Button x:Name="ScanNow" Grid.Column="2" Style="{StaticResource Primary}" VerticalAlignment="Center">
            <StackPanel><StackPanel Orientation="Horizontal" HorizontalAlignment="Center"><TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" FontSize="20" Margin="0,0,8,0"/><TextBlock Text="Scan Now" FontSize="20" FontWeight="SemiBold"/></StackPanel><TextBlock Text="Quick Scan" FontSize="13" Foreground="#E5E0FF" HorizontalAlignment="Center" Margin="0,4,0,0"/></StackPanel>
          </Button>
        </Grid>
      </Border>

      <Grid Grid.Row="2">
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="380"/></Grid.ColumnDefinitions>

        <Grid Grid.Column="0" Margin="0,0,22,0">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Grid Grid.Row="0" Margin="0,0,0,12">
            <StackPanel HorizontalAlignment="Left"><TextBlock Text="Scan Targets" FontSize="22" FontWeight="Bold"/><TextBlock Text="Tap a row to expand  -  tap the box to select" FontSize="13" Foreground="#8A93A6" Margin="0,2,0,0"/></StackPanel>
            <Button x:Name="BtnEdit" Style="{StaticResource Soft}" HorizontalAlignment="Right" VerticalAlignment="Top"><StackPanel Orientation="Horizontal"><TextBlock Text="&#xE70F;" FontFamily="Segoe MDL2 Assets" FontSize="14" Margin="0,0,8,0"/><TextBlock Text="Edit" FontSize="14"/></StackPanel></Button>
          </Grid>
          <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" PanningMode="VerticalOnly"><StackPanel x:Name="TargetsPanel"/></ScrollViewer>
        </Grid>

        <ScrollViewer Grid.Column="1" VerticalScrollBarVisibility="Auto" PanningMode="VerticalOnly">
          <StackPanel>
            <Button x:Name="TileScanAll" Style="{StaticResource Tile}" Margin="0,0,0,10" MinHeight="60"><StackPanel Orientation="Horizontal"><Border Width="40" Height="40" CornerRadius="10" Background="#1A2231"><TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" FontSize="20" Foreground="#8B8BF8" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><StackPanel VerticalAlignment="Center" Margin="14,0,0,0"><TextBlock Text="Scan All" FontSize="16" FontWeight="SemiBold" Foreground="#FFFFFF"/><TextBlock Text="Deep scan everything" FontSize="12" Foreground="#8A93A6" Margin="0,2,0,0"/></StackPanel></StackPanel></Button>
            <Button x:Name="TileScanChecked" Style="{StaticResource Tile}" Margin="0,0,0,10" MinHeight="60"><StackPanel Orientation="Horizontal"><Border Width="40" Height="40" CornerRadius="10" Background="#1A2231"><TextBlock Text="&#xE73E;" FontFamily="Segoe MDL2 Assets" FontSize="20" Foreground="#8B8BF8" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><StackPanel VerticalAlignment="Center" Margin="14,0,0,0"><TextBlock Text="Scan Checked" FontSize="16" FontWeight="SemiBold" Foreground="#FFFFFF"/><TextBlock Text="Scan selected items" FontSize="12" Foreground="#8A93A6" Margin="0,2,0,0"/></StackPanel></StackPanel></Button>
            <Button x:Name="TileUpdateDefs" Style="{StaticResource Tile}" Margin="0,0,0,10" MinHeight="60"><StackPanel Orientation="Horizontal"><Border Width="40" Height="40" CornerRadius="10" Background="#1A2231"><TextBlock Text="&#xE72C;" FontFamily="Segoe MDL2 Assets" FontSize="20" Foreground="#54D98C" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><StackPanel VerticalAlignment="Center" Margin="14,0,0,0"><TextBlock Text="Update Definitions" FontSize="16" FontWeight="SemiBold" Foreground="#FFFFFF"/><TextBlock Text="Update virus database" FontSize="12" Foreground="#8A93A6" Margin="0,2,0,0"/></StackPanel></StackPanel></Button>
            <Button x:Name="TileUpdateApp" Style="{StaticResource Tile}" Margin="0,0,0,10" MinHeight="60"><StackPanel Orientation="Horizontal"><Border Width="40" Height="40" CornerRadius="10" Background="#1A2231"><TextBlock Text="&#xEBD3;" FontFamily="Segoe MDL2 Assets" FontSize="20" Foreground="#8B8BF8" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><StackPanel VerticalAlignment="Center" Margin="14,0,0,0"><TextBlock Text="Update App" FontSize="16" FontWeight="SemiBold" Foreground="#FFFFFF"/><TextBlock Text="Check for updates" FontSize="12" Foreground="#8A93A6" Margin="0,2,0,0"/></StackPanel></StackPanel></Button>
            <Button x:Name="TileLogs" Style="{StaticResource Tile}" Margin="0,0,0,10" MinHeight="60"><StackPanel Orientation="Horizontal"><Border Width="40" Height="40" CornerRadius="10" Background="#1A2231"><TextBlock Text="&#xE8A5;" FontFamily="Segoe MDL2 Assets" FontSize="20" Foreground="#8B8BF8" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><StackPanel VerticalAlignment="Center" Margin="14,0,0,0"><TextBlock Text="View Logs" FontSize="16" FontWeight="SemiBold" Foreground="#FFFFFF"/><TextBlock Text="Browse scan logs" FontSize="12" Foreground="#8A93A6" Margin="0,2,0,0"/></StackPanel></StackPanel></Button>
            <Button x:Name="TileAdd" Style="{StaticResource Tile}" Margin="0,0,0,0" MinHeight="60"><StackPanel Orientation="Horizontal"><Border Width="40" Height="40" CornerRadius="10" Background="#1A2231"><TextBlock Text="&#xE710;" FontFamily="Segoe MDL2 Assets" FontSize="20" Foreground="#8B8BF8" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><StackPanel VerticalAlignment="Center" Margin="14,0,0,0"><TextBlock Text="Add Folder" FontSize="16" FontWeight="SemiBold" Foreground="#FFFFFF"/><TextBlock Text="Pick a folder to scan" FontSize="12" Foreground="#8A93A6" Margin="0,2,0,0"/></StackPanel></StackPanel></Button>
          </StackPanel>
        </ScrollViewer>

        <!-- in-app run / output / logs overlay -->
        <Border x:Name="RunView" Grid.Column="0" Grid.ColumnSpan="2" Background="#070910" Visibility="Collapsed">
          <Grid>
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
            <TextBlock x:Name="RunTitle" Grid.Row="0" Text="Scanning" FontSize="24" FontWeight="Bold"/>
            <ProgressBar x:Name="RunProgress" Grid.Row="1" IsIndeterminate="True" Height="6" Margin="0,12,0,12" Background="#11151F" Foreground="#6D5BF0" BorderThickness="0"/>
            <Grid Grid.Row="2">
              <Grid.ColumnDefinitions><ColumnDefinition x:Name="LogListCol" Width="0"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <Border x:Name="LogListBorder" Grid.Column="0" Margin="0,0,12,0" Visibility="Collapsed">
                <ScrollViewer VerticalScrollBarVisibility="Auto" PanningMode="VerticalOnly"><StackPanel x:Name="LogList"/></ScrollViewer>
              </Border>
              <Border Grid.Column="1" CornerRadius="14" Background="#0B0F18" BorderBrush="#1A2130" BorderThickness="1" Padding="6">
                <TextBox x:Name="RunBox" Background="Transparent" Foreground="#C7CEDA" BorderThickness="0" IsReadOnly="True" FontFamily="Consolas" FontSize="13" TextWrapping="NoWrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
              </Border>
            </Grid>
            <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,14,0,0">
              <Button x:Name="RunBack" Style="{StaticResource Soft}" Content="Back to Dashboard"/>
              <Button x:Name="RunCancel" Style="{StaticResource Soft}" Content="Cancel" Margin="10,0,0,0" Visibility="Collapsed"/>
            </StackPanel>
          </Grid>
        </Border>
      </Grid>

      <Border Grid.Row="3" CornerRadius="14" Background="#0B0F18" BorderBrush="#1A2130" BorderThickness="1" Margin="0,18,0,0" Padding="18,12">
        <Grid>
          <StackPanel Orientation="Horizontal" HorizontalAlignment="Left">
            <TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" FontSize="20" Foreground="#8B8BF8" VerticalAlignment="Center" Margin="0,0,12,0"/>
            <StackPanel><TextBlock Text="On-demand scanner" FontSize="15" FontWeight="SemiBold"/><TextBlock Text="This app scans on demand - it does not provide always-on protection." FontSize="12" Foreground="#8A93A6"/></StackPanel>
          </StackPanel>
          <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
            <TextBlock Text="&#xE701;" FontFamily="Segoe MDL2 Assets" FontSize="18" Foreground="#9BA3B4" Margin="0,0,18,0"/>
            <TextBlock x:Name="StatusBattery" Text="&#xE83F;" FontFamily="Segoe MDL2 Assets" FontSize="18" Foreground="#9BA3B4" Margin="0,0,8,0"/>
            <TextBlock x:Name="StatusTime" Text="" FontSize="15" Foreground="#C7CEDA"/>
          </StackPanel>
        </Grid>
      </Border>
    </Grid>
  </Grid>
</Window>
"@

  try {
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $win = [Windows.Markup.XamlReader]::Load($reader)
  } catch {
    [System.Windows.Forms.MessageBox]::Show("Failed to build the UI: $_",'scan-av') | Out-Null
    return
  }

  $find = { param($n) $win.FindName($n) }
  (& $find 'HeaderInfo').Text = ("Engine: {0}{1}   -   Mode: {2}   -   Incremental: {3}" -f $(if ($cfg.engines.clamav) {'ClamAV '} else {''}), $(if ($cfg.engines.emsisoft) {'Emsisoft'} else {''}), $cfg.options.mode, $(if ($incOn) {'On'} else {'Off'}))
  try {
    $lastLog = Get-ChildItem $LogDir -Filter *.log -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($lastLog) { (& $find 'HeroLast').Text = "Last scan: " + $lastLog.LastWriteTime.ToString('ddd, HH:mm') }
  } catch {}
  try { (& $find 'StatusTime').Text = (Get-Date).ToString('HH:mm') } catch {}

  $script:TargetsPanel = (& $find 'TargetsPanel')
  $script:runView      = (& $find 'RunView')
  $script:runTitle     = (& $find 'RunTitle')
  $script:runProgress  = (& $find 'RunProgress')
  $script:runBox       = (& $find 'RunBox')
  $script:runBack      = (& $find 'RunBack')
  $script:runCancel    = (& $find 'RunCancel')
  $script:logListBorder = (& $find 'LogListBorder')
  $script:logListCol    = (& $find 'LogListCol')
  $script:logList       = (& $find 'LogList')
  $script:runTimer    = $null; $script:runProc = $null
  Rebuild-Roots

  $confirm = { param($msg) (([System.Windows.MessageBox]::Show($msg,'scan-av','YesNo','Question')) -eq 'Yes') }
  $scanChecked = {
    $sel = @(Collect-Targets)
    if (-not $sel.Count) { [System.Windows.MessageBox]::Show('Nothing checked. Tick at least one item, or use Scan All.','scan-av') | Out-Null; return }
    if (-not (& $confirm ("Scan {0} selected item(s) now?" -f $sel.Count))) { return }
    $pathExpr = ($sel | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','
    Start-InAppRun 'Scanning selected items' ("-Path $pathExpr")
  }
  $doUpdateApp = {
    if (-not (& $confirm 'Check GitHub and download the latest app version?')) { return }
    $r = Update-FromGitHub
    if ($r.ok) {
      $a = [System.Windows.MessageBox]::Show("$($r.msg)`n`nRestart the app now?",'scan-av','YesNo','Question')
      if ($a -eq 'Yes') { Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File', ('"{0}"' -f $ps1), '-Gui'); $win.Close() }
    } else { [System.Windows.MessageBox]::Show($r.msg,'scan-av') | Out-Null }
  }
  $openCfg = { Start-Process -FilePath 'powershell.exe' -ArgumentList ("-NoExit -NoProfile -ExecutionPolicy Bypass -Command `"& '{0}' -Configure`"" -f ($ps1 -replace "'", "''")) }

  $scanAll = { if (& $confirm 'Scan ALL configured folders now? This can take a while.') { Start-InAppRun 'Scanning all folders' '' } }
  $updateDefs = { if (& $confirm 'Update virus definitions now? This downloads from ClamAV and Emsisoft.') { Start-InAppRun 'Updating definitions' '-Update' } }
  (& $find 'ScanNow').Add_Click({ $sel = @(Collect-Targets); if ($sel.Count) { & $scanChecked } else { & $scanAll } })
  (& $find 'TileScanAll').Add_Click($scanAll)
  (& $find 'TileScanChecked').Add_Click({ & $scanChecked })
  (& $find 'TileUpdateDefs').Add_Click($updateDefs)
  (& $find 'TileLogs').Add_Click({ Show-LogsInApp })
  (& $find 'TileUpdateApp').Add_Click($doUpdateApp)
  (& $find 'TileAdd').Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
      $p = $dlg.SelectedPath
      if (@($script:guiCfg.scanFolders) -notcontains $p) { $script:guiCfg.scanFolders = @(@($script:guiCfg.scanFolders) + $p); Save-GuiCfg; Rebuild-Roots }
    }
  })
  (& $find 'BtnEdit').Add_Click({
    $tops = @($script:rootNodes | Where-Object { $_.Checked } | ForEach-Object { $_.Path })
    if (-not $tops.Count) { [System.Windows.MessageBox]::Show('Check the top-level folder(s) to remove, then tap Edit.','scan-av') | Out-Null; return }
    $a = [System.Windows.MessageBox]::Show(("Remove {0} folder(s) from the scan list?" -f $tops.Count),'scan-av','YesNo','Question')
    if ($a -eq 'Yes') { $script:guiCfg.scanFolders = @(@($script:guiCfg.scanFolders) | Where-Object { $tops -notcontains $_ }); Save-GuiCfg; Rebuild-Roots }
  })
  (& $find 'RunBack').Add_Click({ if ($script:runTimer) { $script:runTimer.Stop() }; $script:runView.Visibility = 'Collapsed' })
  (& $find 'RunCancel').Add_Click({ if (& $confirm 'Cancel the running operation?') { Stop-InAppRun } })
  (& $find 'NavDashboard').Add_Click({ $script:runView.Visibility = 'Collapsed' })
  (& $find 'NavScan').Add_Click({ & $scanChecked })
  (& $find 'NavUpdates').Add_Click($updateDefs)
  (& $find 'NavLogs').Add_Click({ Show-LogsInApp })
  (& $find 'NavSettings').Add_Click($openCfg)
  (& $find 'BtnSettings').Add_Click($openCfg)
  (& $find 'BtnMore').Add_Click($doUpdateApp)
  (& $find 'NavAbout').Add_Click({ [System.Windows.MessageBox]::Show("scan-av`nOn-demand malware scanner for handhelds.`nClamAV + Emsisoft.`ngithub.com/dggomes/avscan",'About scan-av') | Out-Null })
  (& $find 'NavProtection').Add_Click({ [System.Windows.MessageBox]::Show('scan-av is an on-demand scanner: it checks files when you run a scan. It does not provide always-on/real-time protection.','Protection') | Out-Null })

  [void]$win.ShowDialog()
}
# ---------------------------------------------------------------- scan cache
# Tracks already-scanned items so unchanged ones are skipped. Keyed by full path;
# a "signature" of size+mtime (file) or count+size+newest-mtime (folder) detects
# changes without hashing file contents.
function Get-Signature {
  param([string]$Path)
  try {
    $it = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($it.PSIsContainer) {
      $count = 0; $size = [long]0; $maxT = [long]0
      Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $count++; $size += $_.Length
        $t = $_.LastWriteTimeUtc.Ticks; if ($t -gt $maxT) { $maxT = $t }
      }
      return "D|$count|$size|$maxT"
    }
    return "F|$($it.Length)|$($it.LastWriteTimeUtc.Ticks)"
  } catch { return $null }
}
function Load-Cache {
  $h = @{}
  if (Test-Path $CacheFile) {
    try {
      $j = Get-Content $CacheFile -Raw | ConvertFrom-Json
      if ($j.entries) { foreach ($p in $j.entries.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    } catch {}
  }
  return $h
}
function Save-Cache {
  param([hashtable]$Cache)
  $o = [ordered]@{ version = 1; entries = [ordered]@{} }
  foreach ($k in $Cache.Keys) { $o.entries[$k] = $Cache[$k] }
  try { ($o | ConvertTo-Json -Depth 6) | Set-Content -Path $CacheFile -Encoding UTF8 } catch { Warn "Could not save scan cache: $_" }
}

# ================================================================ MAIN
if ($Install)          { Invoke-Install; return }
if ($InstallEngines)   { Install-Engines; return }
if ($Shortcut)         { New-DesktopShortcut -Elevated $true; return }
if ($NoPromptShortcut) { Register-NoPromptTask; return }
if ($Gui)              { Show-Gui; return }
if ($SelfUpdate)       { $r = Update-FromGitHub; if ($r.ok) { Ok $r.msg } else { Bad $r.msg }; return }
if ($InstallContextMenu) { Install-ContextMenu; return }
if ($RemoveContextMenu)  { Remove-ContextMenu; return }
if ($Configure)        { Invoke-Configure | Out-Null; return }

# manage the saved scan-folder list without re-running the whole wizard
if ($AddFolder -or $RemoveFolder -or $ListFolders) {
  $cfg = Load-Config
  if (-not $cfg) { Bad 'No config yet. Run: scan-av -Install   (or scan-av -Configure)'; return }
  $list = @($cfg.scanFolders)
  foreach ($f in $AddFolder) {
    $rf = try { (Resolve-Path -LiteralPath $f -ErrorAction Stop).Path } catch { $f }
    if (-not (Test-Path $rf)) { Warn "  path not found (added anyway): $rf" }
    if ($list -notcontains $rf) { $list += $rf; Ok "added: $rf" } else { Info "already present: $rf" }
  }
  foreach ($f in $RemoveFolder) {
    $rf = try { (Resolve-Path -LiteralPath $f -ErrorAction Stop).Path } catch { $f }
    if ($list -contains $rf) { $list = @($list | Where-Object { $_ -ne $rf }); Ok "removed: $rf" } else { Info "not in list: $rf" }
  }
  if ($AddFolder -or $RemoveFolder) {
    $cfg.scanFolders = @($list)
    try { ($cfg | ConvertTo-Json -Depth 6) | Set-Content -Path $CfgFile -Encoding UTF8 } catch { Bad "Could not save config: $_"; return }
  }
  Sec 'Configured scan folders'
  if (@($cfg.scanFolders).Count) { @($cfg.scanFolders) | ForEach-Object { Info "  $_" } } else { Info '  (none)' }
  return
}

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

# Auto-elevate: Emsisoft's a2cmd requires admin and self-elevates into a separate
# window mid-scan. Relaunch the whole run elevated first (ONE UAC prompt) so a2cmd
# runs inline. Skipped if already admin (e.g. launched from the elevated shortcut),
# if -NoElevate, if config disables it, or if Emsisoft isn't part of this run.
$autoElev = if ($null -ne $cfg.options.autoElevate) { [bool]$cfg.options.autoElevate } else { $true }
if (($engines -contains 'emsisoft') -and $autoElev -and -not $NoElevate -and -not (Test-IsAdmin)) {
  Info 'Emsisoft needs admin - relaunching elevated (one UAC prompt)...'
  if (Invoke-RelaunchElevated -Bound $PSBoundParameters) { return }
  Warn 'Not elevated; Emsisoft may open its own UAC window. (Use -NoElevate to silence this, or -Engine clamav.)'
}

# -Verbose streams each engine's live per-file output to the console
$script:LiveScan = ($VerbosePreference -ne 'SilentlyContinue')
if ($script:LiveScan) { Info 'Verbose: streaming live engine output.' }

# definition updates: -Update forces; -NoUpdate skips; otherwise auto-update when the
# config enables it AND definitions are older than options.updateMaxAgeHours.
$doUpdate = $false
if ($Update) {
  $doUpdate = $true
} elseif (-not $NoUpdate) {
  $auto = if ($null -ne $cfg.options.autoUpdate) { [bool]$cfg.options.autoUpdate } else { $true }
  if ($auto) {
    $maxAge = if ($cfg.options.updateMaxAgeHours) { [double]$cfg.options.updateMaxAgeHours } else { 12 }
    $stamp  = Join-Path $AppDir 'last-update.txt'
    $ageH   = $null
    if (Test-Path $stamp) {
      try { $ageH = ([DateTime]::UtcNow - [DateTime]::Parse((Get-Content $stamp -Raw).Trim()).ToUniversalTime()).TotalHours } catch { $ageH = $null }
    }
    if (($null -eq $ageH) -or ($ageH -ge $maxAge)) { $doUpdate = $true }
    else { Info ("Definitions updated {0:N1}h ago (< {1}h) - skipping. Use -Update to force." -f $ageH, $maxAge) }
  }
}
if ($doUpdate) { Update-Definitions -Cfg $cfg -Engines $engines | Out-Null }

# targets
$targets = if ($Path) { $Path } else { $cfg.scanFolders }
if (-not $targets) { Warn 'Nothing to scan. Pass -Path <file/folder> or add folders via -Configure.'; return }

# incremental scan-cache: skip already-scanned, unchanged items
$incremental = if ($null -ne $cfg.options.incremental) { [bool]$cfg.options.incremental } else { $true }
if ($NoIncremental) { $incremental = $false }
$cache = if ($incremental) { Load-Cache } else { @{} }

# Feature: ask whether to re-scan everything or only new/changed (when a cache exists)
$rescanAll = [bool]$RescanAll
if ($incremental -and -not $rescanAll -and $cache.Count -gt 0) {
  try {
    $ans = Read-Host 'Re-scan ALL items, or only NEW/CHANGED since last scan? (a = All / Enter = new only)'
    if ($ans -match '^\s*[Aa]') { $rescanAll = $true }
  } catch {}   # non-interactive host -> keep new-only
}

# expand folder targets into immediate children so whole unchanged items get skipped
$units = @()
foreach ($t in $targets) {
  if ($incremental -and (Test-Path $t -PathType Container)) {
    Get-ChildItem -LiteralPath $t -Force -ErrorAction SilentlyContinue | ForEach-Object { $units += $_.FullName }
  } else { $units += $t }
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$tag = if ($incremental -and -not $rescanAll) { ' (incremental)' } elseif ($rescanAll) { ' (rescan all)' } else { '' }
Sec ("scan-av  -  engines: {0}   mode: {1}   items: {2}{3}" -f ($engines -join '+'), $cfg.options.mode, @($units).Count, $tag)

$all = @(); $skipped = 0
foreach ($u in $units) {
  $sig = if ($incremental) { Get-Signature $u } else { $null }
  $entry = $cache[$u]
  if ($incremental -and -not $rescanAll -and $entry -and ($entry.result -eq 'clean') -and $sig -and ($entry.sig -eq $sig)) {
    Ok ("cached (clean), skipping: {0}" -f (Split-Path $u -Leaf)); $skipped++; continue
  }
  $r = Scan-Target -Target $u -Cfg $cfg -Engines $engines
  if ($r) {
    $all += $r
    if ($incremental) {
      if ($r.Hits -eq 0) { $cache[$u] = @{ sig = $sig; utc = ([DateTime]::UtcNow.ToString('o')); result = 'clean' } }
      elseif ($cache.ContainsKey($u)) { $cache.Remove($u) }   # infected -> don't remember as clean
    }
  }
}
if ($incremental) { Save-Cache -Cache $cache }

# final summary
Write-Host ''
Sec 'SUMMARY'
$threats = @($all | Where-Object { $_.Hits -gt 0 })
foreach ($r in $all) {
  if ($r.Hits -gt 0) { Bad ("  THREAT  {0}  ({1} hit(s))" -f $r.Target, $r.Hits) }
  else               { Ok  ("  clean   {0}" -f $r.Target) }
}
if ($skipped -gt 0) { Info ("  cached  {0} unchanged item(s) skipped" -f $skipped) }
Write-Host ''
if ($threats)               { Bad ("{0} of {1} scanned item(s) flagged. Review logs in $LogDir and verify on VirusTotal." -f $threats.Count, $all.Count) }
elseif ($all.Count -eq 0)   { Ok  ("Nothing new - all {0} item(s) already scanned & unchanged." -f $skipped) }
else                        { Ok  ("All {0} scanned item(s) clean{1}." -f $all.Count, $(if ($skipped) { " ($skipped skipped, unchanged)" } else { '' })) }
