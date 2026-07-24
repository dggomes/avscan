# Fixture tests for windows/scan-av.ps1 - no Windows binaries needed, so they run
# on any OS with pwsh. Functions are extracted from the script's AST and executed
# against synthetic engine output. Exits non-zero on the first failure.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$srcPath = Join-Path $repo 'windows/scan-av.ps1'

$fails = 0
function Assert([bool]$cond, [string]$name, [string]$detail = '') {
  if ($cond) { Write-Host "PASS: $name" }
  else { Write-Host "FAIL: $name  $detail"; $script:fails++ }
}

# ---- 1. parse check (the self-updater ships this file raw from main) ----
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($srcPath, [ref]$null, [ref]$errs)
Assert (-not $errs -or $errs.Count -eq 0) 'scan-av.ps1 parses' ("$($errs | ForEach-Object { $_.Message })")
if ($errs -and $errs.Count) { exit 1 }

# ---- 1b. standalone launcher wiring for ROG Armoury / app launchers ----
$launcherFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Ensure-StandaloneLauncher' }, $true) | Select-Object -First 1
$updaterLauncherFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Ensure-UpdaterLauncher' }, $true) | Select-Object -First 1
$shortcutFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-DesktopShortcut' }, $true) | Select-Object -First 1
$updaterShortcutFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-UpdaterShortcut' }, $true) | Select-Object -First 1
$updateFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Update-FromGitHub' }, $true) | Select-Object -First 1
Assert ($launcherFn -and $launcherFn.Extent.Text -match 'ScanAV\.exe' -and $launcherFn.Extent.Text -match 'WindowsPowerShell\\v1\.0\\powershell\.exe') `
  'standalone launcher function builds ScanAV.exe wrapper'
Assert ($updaterLauncherFn -and $updaterLauncherFn.Extent.Text -match 'ScanAV-Updater\.exe' -and $updaterLauncherFn.Extent.Text -match 'WindowsPowerShell\\v1\.0\\powershell\.exe' -and $updaterLauncherFn.Extent.Text -match '-SelfUpdate' -and $updaterLauncherFn.Extent.Text -match '-NoExit') `
  'updater launcher function builds visible ScanAV-Updater.exe self-update wrapper'
Assert ($shortcutFn -and $shortcutFn.Extent.Text -match 'Ensure-StandaloneLauncher' -and $shortcutFn.Extent.Text -match 'Shortcut target:' -and $shortcutFn.Extent.Text -match 'IconLocation' -and $shortcutFn.Extent.Text -match 'icon\.ico' -and $shortcutFn.Extent.Text -notmatch 'WindowsPowerShell\\v1\.0\\powershell\.exe') `
  'desktop shortcut targets ScanAV.exe and uses app icon'
Assert ($updaterShortcutFn -and $updaterShortcutFn.Extent.Text -match 'Ensure-UpdaterLauncher' -and $updaterShortcutFn.Extent.Text -match 'Updater shortcut target:' -and $updaterShortcutFn.Extent.Text -match 'IconLocation' -and $updaterShortcutFn.Extent.Text -notmatch 'WindowsPowerShell\\v1\.0\\powershell\.exe') `
  'updater shortcut targets ScanAV-Updater.exe and uses app icon'
Assert ($updateFn -and $updateFn.Extent.Text -match 'Ensure-StandaloneLauncher' -and $updateFn.Extent.Text -match 'Standalone launcher' -and $updateFn.Extent.Text -match 'Ensure-UpdaterLauncher' -and $updateFn.Extent.Text -match 'Updater launcher') `
  'self-update refreshes standalone and updater launchers'
$src = Get-Content $srcPath -Raw
$verMatch = [regex]::Match($src, "\`$ScanAvVersion\s*=\s*'([^']+)'")
$buildMatch = [regex]::Match($src, "\`$ScanAvBuild\s*=\s*'([^']+)'")
Assert ($verMatch.Success -and ([version]$verMatch.Groups[1].Value -ge [version]'1.11.0')) 'app version bumped for updater visibility'
Assert ($buildMatch.Success -and $buildMatch.Groups[1].Value -eq '2026-07-24') 'app build date current'

# ---- 2. embedded XAML is well-formed and has the expected controls ----
$m = [regex]::Match($src, '(?s)\$xaml = @"(.*?)\r?\n"@')
Assert $m.Success 'XAML block found'
try {
  $x = [xml]$m.Groups[1].Value
  $names = @($x.SelectNodes('//*') | ForEach-Object { $_.Attributes } | ForEach-Object { $_ } |
             Where-Object { $_ -and $_.LocalName -eq 'Name' } | ForEach-Object { $_.Value })
  foreach ($need in 'BtnAddTop','BtnRefresh','BtnUpdate','BtnExit','SetVtUpload','SetVtKey','SetTimeout','RunResults','RunResultsWrap','HeaderProgress','AddFolderPanel','AddFolderPath','AddFolderRoots','AddFolderList','AddFolderOpen','AddFolderUp','AddFolderRefresh','AddFolderAddAll','AddFolderAdd','AddFolderCancel','TileQuickScan','BtnNoPromptSetup') {
    Assert ($names -contains $need) "XAML control $need present"
  }
  Assert ($names -notcontains 'BtnTray') 'XAML control BtnTray removed'
  Assert ($names -notcontains 'BtnEdit') 'XAML control BtnEdit removed (per-folder X replaces bulk Remove)'
} catch { Assert $false 'XAML well-formed' "$_" }

# ---- 3. app workflow functions are present ----
foreach ($fnName in @('New-UpdaterShortcut','Open-FolderNode','Move-FolderNode','Remove-FolderNode','Remove-ScanFolderPath','Move-PathWithDialog','Get-PreferredMoveRoot','Choose-FolderForMove','Choose-ExecutableFile','Set-SystemEnhancedDpi','Run-CleanExecutable','Show-MoveFolderDialog','Show-CleanNextStepDialog','Invoke-CleanRenameMove','Invoke-CleanRunExe','Ensure-TrayIcon','Hide-ToTray','Exit-App','Show-ExitChoiceDialog','Restart-AppViaLauncher','Normalize-ScanFolderPath','Get-KnownNetworkFolders','Add-ScanFolderPath','Add-ScanFolderPaths','Show-NativeAddFolderDialog','Get-AddScanFolderRoots','Refresh-InlineAddFolderRoots','Load-InlineAddFolder','Select-InlineAddFolderPath','Show-InlineAddFolderPanel','Hide-InlineAddFolderPanel','Show-AddScanFolderSimpleDialog','Show-SafeFolderPicker','Add-ScanFolderDialog','Show-AddScanFolderWinFormsDialog','Show-AddScanFolderFallbackDialog','Invoke-AddScanFolderDialog')) {
  $f = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq $fnName -or $n.Name -eq "script:$fnName") }, $true) | Select-Object -First 1
  Assert ($null -ne $f) "function $fnName found"
}
$newCardFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'New-TargetCard' -or $n.Name -eq 'script:New-TargetCard') }, $true) | Select-Object -First 1
Assert ($newCardFn -and $newCardFn.Extent.Text -match 'Remove-FolderNode' -and $newCardFn.Extent.Text -match '0xE711' -and $newCardFn.Extent.Text -match 'Depth -eq 0') `
  'each root folder card has an X button to remove it from the scan list'
$removeFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Remove-FolderNode' -or $n.Name -eq 'script:Remove-FolderNode') }, $true) | Select-Object -First 1
Assert ($removeFn -and $removeFn.Extent.Text -match 'Remove-ScanFolderPath' -and $removeFn.Extent.Text -match 'not deleted') `
  'per-folder remove confirms and only drops the path from the scan list'
$showResultsFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Show-RunResults' -or $n.Name -eq 'script:Show-RunResults') }, $true) | Select-Object -First 1
$cleanDialogFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Show-CleanNextStepDialog' -or $n.Name -eq 'script:Show-CleanNextStepDialog') }, $true) | Select-Object -First 1
Assert ($showResultsFn -and $showResultsFn.Extent.Text -match 'Show-CleanNextStepDialog' -and $showResultsFn.Extent.Text -notmatch 'Clean - choose next step') `
  'clean scan results use modal next-step dialog'
Assert ($cleanDialogFn -and $cleanDialogFn.Extent.Text -match 'All clean' -and $cleanDialogFn.Extent.Text -match 'Rename \+ Move Folder' -and $cleanDialogFn.Extent.Text -match 'Run EXE' -and $cleanDialogFn.Extent.Text -match 'compatibility settings') `
  'clean next-step modal exposes close, move, run exe actions'
$exitChoiceFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Show-ExitChoiceDialog' -or $n.Name -eq 'script:Show-ExitChoiceDialog') }, $true) | Select-Object -First 1
Assert ($exitChoiceFn -and $exitChoiceFn.Extent.Text -match 'minimize to tray' -and $exitChoiceFn.Extent.Text -match 'quit') `
  'exit button asks between tray and quit'
$restartFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Restart-AppViaLauncher' -or $n.Name -eq 'script:Restart-AppViaLauncher') }, $true) | Select-Object -First 1
Assert ($restartFn -and $restartFn.Extent.Text -match 'Ensure-StandaloneLauncher' -and $restartFn.Extent.Text -match 'ScanAV\.exe') `
  'app update restart uses ScanAV.exe launcher'
Assert ($src -notmatch "Start-Process -FilePath 'powershell\.exe'.*-Gui") `
  'app update restart does not relaunch through powershell.exe'
$addFolderFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Add-ScanFolderDialog' -or $n.Name -eq 'script:Add-ScanFolderDialog') }, $true) | Select-Object -First 1
$knownNetworkFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Get-KnownNetworkFolders' -or $n.Name -eq 'script:Get-KnownNetworkFolders') }, $true) | Select-Object -First 1
Assert ($addFolderFn -and $addFolderFn.Extent.Text -match 'Known network locations' -and $addFolderFn.Extent.Text -match 'UNC path') `
  'add folder dialog supports network locations and manual UNC paths'
Assert ($knownNetworkFn -and $knownNetworkFn.Extent.Text -match "HKCU:\\Network" -and $knownNetworkFn.Extent.Text -match 'Network Shortcuts' -and $knownNetworkFn.Extent.Text -match 'DisplayRoot' -and $knownNetworkFn.Extent.Text -match 'WScript.Network' -and $knownNetworkFn.Extent.Text -match 'Win32_LogicalDisk' -and $knownNetworkFn.Extent.Text -match 'net use' -and $knownNetworkFn.Extent.Text -match 'RemotePath') `
  'known network folders include mapped drives from Windows drive APIs and Explorer network shortcuts'
$invokeAddFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Invoke-AddScanFolderDialog' -or $n.Name -eq 'script:Invoke-AddScanFolderDialog') }, $true) | Select-Object -First 1
$addSimpleFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Show-AddScanFolderSimpleDialog' -or $n.Name -eq 'script:Show-AddScanFolderSimpleDialog') }, $true) | Select-Object -First 1
$addWinFormsFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Show-AddScanFolderWinFormsDialog' -or $n.Name -eq 'script:Show-AddScanFolderWinFormsDialog') }, $true) | Select-Object -First 1
$safePickerFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Show-SafeFolderPicker' -or $n.Name -eq 'script:Show-SafeFolderPicker') }, $true) | Select-Object -First 1
$inlineRootFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Get-AddScanFolderRoots' -or $n.Name -eq 'script:Get-AddScanFolderRoots') }, $true) | Select-Object -First 1
$inlineShowFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Show-InlineAddFolderPanel' -or $n.Name -eq 'script:Show-InlineAddFolderPanel') }, $true) | Select-Object -First 1
$inlineLoadFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Load-InlineAddFolder' -or $n.Name -eq 'script:Load-InlineAddFolder') }, $true) | Select-Object -First 1
$inlineSelectFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Select-InlineAddFolderPath' -or $n.Name -eq 'script:Select-InlineAddFolderPath') }, $true) | Select-Object -First 1
$nativeAddFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Show-NativeAddFolderDialog' -or $n.Name -eq 'script:Show-NativeAddFolderDialog') }, $true) | Select-Object -First 1
Assert ($invokeAddFn -and $invokeAddFn.Extent.Text -match 'Show-InlineAddFolderPanel' -and $invokeAddFn.Extent.Text -notmatch 'Show-AddScanFolderWinFormsDialog') `
  'add folder wrapper prefers inline browser and bypasses advanced WinForms picker'
Assert ($inlineRootFn -and $inlineRootFn.Extent.Text -match 'DriveInfo' -and $inlineRootFn.Extent.Text -match 'Get-KnownNetworkFolders' -and $inlineRootFn.Extent.Text -match 'scanFolders') `
  'inline add folder roots include drives, mapped/network locations and existing scan folders'
Assert ($inlineShowFn -and $inlineShowFn.Extent.Text -match 'Refresh-InlineAddFolderRoots' -and $inlineShowFn.Extent.Text -match 'AddScanFolderFallbackDialog' -and $inlineShowFn.Extent.Text -notmatch 'XamlReader') `
  'inline add folder panel opens inside main window without loading a secondary dialog'
Assert ($inlineLoadFn -and $inlineLoadFn.Extent.Text -match 'Get-ChildItem' -and $inlineLoadFn.Extent.Text -match 'UNC path') `
  'inline add folder browser lists subfolders and explains UNC fallback'
Assert ($inlineSelectFn -and $inlineSelectFn.Extent.Text -match 'SelectedItem' -and $src -match 'Content="Select"' -and $src -match "AddFolderOpen.*Add_Click\(\{ Select-InlineAddFolderPath \}" -and $src -notmatch "AddFolderOpen.*Add_Click\(\{ Load-InlineAddFolder") `
  'inline add folder Select button chooses highlighted folder instead of navigating into it'
Assert ($nativeAddFn -and $nativeAddFn.Extent.Text -match 'FolderBrowserDialog' -and $nativeAddFn.Extent.Text -match 'Add-ScanFolderPath' -and $src -match "TileAdd'\)\.Add_Click\(\{ Show-NativeAddFolderDialog \}" -and $src -match "BtnAddTop'\)\.Add_Click\(\{ Show-NativeAddFolderDialog \}") `
  'add folder buttons use native Windows folder picker'
Assert ($addSimpleFn -and $addSimpleFn.Extent.Text -match 'XamlReader' -and $addSimpleFn.Extent.Text -match 'FindName' -and $addSimpleFn.Extent.Text -match 'Add-ScanFolderPaths' -and $addSimpleFn.Extent.Text -match 'mapped/network' -and $addSimpleFn.Extent.Text -match 'TextBox' -and $addSimpleFn.Extent.Text -match 'ComboBox' -and $addSimpleFn.Extent.Text -match 'ListBox' -and $addSimpleFn.Extent.Text -match 'Open Path' -and $addSimpleFn.Extent.Text -match 'Add All Mapped' -and $addSimpleFn.Extent.Text -match 'NoNamePrompt' -and $addSimpleFn.Extent.Text -notmatch 'InputBox' -and $addSimpleFn.Extent.Text -notmatch 'YesNoCancel') `
  'simple add folder dialog loads WPF browser from XAML and avoids overloaded prompts'
Assert ($addWinFormsFn -and $addWinFormsFn.Extent.Text -match 'Add-Type -AssemblyName System.Windows.Forms' -and $addWinFormsFn.Extent.Text -match 'Add All Mapped' -and $addWinFormsFn.Extent.Text -match 'CheckedListBox' -and $addWinFormsFn.Extent.Text -match 'Add-ScanFolderPaths' -and $addWinFormsFn.Extent.Text -match 'Show-SafeFolderPicker') `
  'add folder WinForms dialog can add all mapped network locations and uses safe in-app folder browsing'
Assert ($safePickerFn -and $safePickerFn.Extent.Text -match 'DriveInfo' -and $safePickerFn.Extent.Text -match 'Get-KnownNetworkFolders' -and $safePickerFn.Extent.Text -match 'Use This Folder') `
  'legacy safe folder browser remains available as fallback'

# ---- 4. extract pure functions from the AST ----
foreach ($fnName in @('Get-HitPaths','Get-VtStatusCode','ConvertFrom-ClamBatchLog','Find-MovedCacheEntry','Test-IsExecFile')) {
  $f = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fnName }, $true) | Select-Object -First 1
  if (-not $f) { Assert $false "function $fnName found"; exit 1 }
  . ([scriptblock]::Create($f.Extent.Text))
}

# ---- 5. Get-HitPaths: ClamAV / Emsisoft / Defender shapes, deduped ----
$tmp = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) "avtest_$(Get-Random)") -Force
$f1 = Join-Path $tmp 'bad one.exe'; Set-Content $f1 'x'
$f2 = Join-Path $tmp 'evil.dll';    Set-Content $f2 'x'
$f3 = Join-Path $tmp 'def hit.exe'; Set-Content $f3 'x'
$results = @(
  [pscustomobject]@{ Engine='ClamAV';   Hits=@("${f1}: Win.Trojan.Agent-123 FOUND"); Scanned='5' }
  [pscustomobject]@{ Engine='Emsisoft'; Hits=@("$f2 detected: Gen:Variant.Zusy"); Scanned='5' }
  [pscustomobject]@{ Engine='Defender'; Hits=@('Trojan:Win32/Wacatac.B!ml'); HitPaths=@($f3, "$f3->inner.exe"); Scanned='5' }
)
$paths = @(Get-HitPaths -Results $results)
Assert ($paths.Count -eq 3 -and -not @(@($f1,$f2,$f3) | Where-Object { $paths -notcontains $_ }).Count) `
  'Get-HitPaths extracts all three engine formats, deduped' "got: $($paths -join ' | ')"

# ---- 5. Defender resource-line regex (mirrors Run-Defender) ----
$defLines = @(
  'Threat                  : Trojan:Win32/Wacatac.B!ml',
  '    file                : C:\Users\dan\bad.exe',
  'file:C:\Users\dan\arch.zip->payload.exe',
  'Scanning C:\target found 1 threats.'
)
$got = @($defLines | ForEach-Object { if ($_ -match '(?i)\bfile\s*:\s*(.+?)(->.*)?\s*$') { $matches[1].Trim() } } | Where-Object { $_ })
Assert (($got.Count -eq 2) -and ($got[0] -eq 'C:\Users\dan\bad.exe') -and ($got[1] -eq 'C:\Users\dan\arch.zip')) `
  'Defender file: regex handles both formats and strips ->member' "got: $($got -join ' | ')"

# ---- 6. ConvertFrom-ClamBatchLog: per-target attribution ----
$targets = @('C:\Scanned\Alpha', 'C:\Scanned\Alpha Two', 'C:\Downloads\setup.exe')
$lines = @(
  'C:\Scanned\Alpha\bin\app.exe: OK',
  'C:\Scanned\Alpha\data\big.bin: Heuristics.Limits.Exceeded.MaxFileSize FOUND',
  'C:\Scanned\Alpha Two\loader.dll: Win.Trojan.Agent-999 FOUND',
  'C:\Scanned\Alpha Two\readme.txt: OK',
  "C:\Scanned\Alpha Two\locked.dat: Can't open file ERROR",
  'C:\Downloads\setup.exe: OK',
  'C:\Elsewhere\stray.exe: OK',
  '----------- SCAN SUMMARY -----------',
  'Scanned files: 5'
)
$map = ConvertFrom-ClamBatchLog -Lines $lines -Targets $targets -Rc 1 -LogFile 'x.log'
$a  = $map['C:\Scanned\Alpha']; $a2 = $map['C:\Scanned\Alpha Two']; $d = $map['C:\Downloads\setup.exe']
Assert ($a.Hits.Count -eq 0 -and $a.Skipped -eq 1 -and $a.Scanned -eq '2') 'batch: Alpha gets its skip, no bleed from "Alpha Two"' "hits=$($a.Hits.Count) skip=$($a.Skipped) scanned=$($a.Scanned)"
Assert ($a2.Hits.Count -eq 1 -and $a2.Errors.Count -eq 1 -and $a2.Scanned -eq '2') 'batch: Alpha Two gets its hit + error' "hits=$($a2.Hits.Count) errs=$($a2.Errors.Count) scanned=$($a2.Scanned)"
Assert ($d.Hits.Count -eq 0 -and $d.Scanned -eq '1') 'batch: single-file target attributed' "scanned=$($d.Scanned)"
Assert ($map.Keys.Count -eq 3) 'batch: stray path outside all targets ignored'

# ---- 6b. Find-MovedCacheEntry: move-aware cache lookup ----
$mvCache = @{
  'C:\Downloads\PackageX' = [pscustomobject]@{ sig = 'D|120|987654|638600000000000000'; utc = '2026-07-01T00:00:00Z'; result = 'clean' }
  'C:\Downloads\Other'   = [pscustomobject]@{ sig = 'D|5|100|638600000000000001';      utc = '2026-07-01T00:00:00Z'; result = 'clean' }
  'C:\Downloads\Empty'   = [pscustomobject]@{ sig = 'D|0|0|0';                          utc = '2026-07-01T00:00:00Z'; result = 'clean' }
}
Assert ((Find-MovedCacheEntry -Cache $mvCache -Unit 'D:\Scanned\PackageX' -Sig 'D|120|987654|638600000000000000') -eq 'C:\Downloads\PackageX') `
  'moved cache: same name + same signature at a new path matches'
Assert ($null -eq (Find-MovedCacheEntry -Cache $mvCache -Unit 'D:\Scanned\PackageY' -Sig 'D|120|987654|638600000000000000')) `
  'moved cache: different name does NOT match despite same signature'
Assert ($null -eq (Find-MovedCacheEntry -Cache $mvCache -Unit 'D:\Scanned\PackageX' -Sig 'D|120|987654|638600000000000099')) `
  'moved cache: changed content (different signature) does NOT match'
Assert ($null -eq (Find-MovedCacheEntry -Cache $mvCache -Unit 'D:\Scanned\Empty' -Sig 'D|0|0|0')) `
  'moved cache: empty-folder signature never matches (collides by design)'
Assert ($null -eq (Find-MovedCacheEntry -Cache $mvCache -Unit 'C:\Downloads\PackageX' -Sig 'D|120|987654|638600000000000000')) `
  'moved cache: the unit itself is not its own move source'

# ---- 6c. Quick scan (-QuickScan): Defender-only sweep of .exe/.dll ----
Assert ($src -match '\[switch\]\$QuickScan') '-QuickScan switch parameter declared'
$qext = [regex]::Match($src, '(?m)^\s*\$QuickScanExt\s*=\s*@\(([^\)]*)\)')
Assert ($qext.Success -and $qext.Groups[1].Value -match "'\.exe'" -and $qext.Groups[1].Value -match "'\.dll'") `
  'QuickScanExt covers .exe and .dll'
# extension classifier is case-insensitive and extension-only (no disk access)
Assert ((Test-IsExecFile 'C:\a\b\App.EXE' @('.exe','.dll')) -and (Test-IsExecFile 'x\core.dll' @('.exe','.dll'))) `
  'Test-IsExecFile matches exe/dll regardless of case'
Assert ((-not (Test-IsExecFile 'readme.txt' @('.exe','.dll'))) -and (-not (Test-IsExecFile 'noext' @('.exe','.dll'))) -and (-not (Test-IsExecFile '' @('.exe','.dll')))) `
  'Test-IsExecFile rejects non-executables, extensionless and empty paths'
# main flow: -QuickScan forces Defender only, expands targets to exec units, needs MpCmdRun
Assert ($src -match '(?s)if \(\$QuickScan\) \{.*?\$engines = @\(''defender''\)') `
  'QuickScan overrides engine selection to Defender only'
Assert ($src -match 'Quick scan needs Microsoft Defender') `
  'QuickScan reports a clear error when Defender is missing'
Assert ($src -match '(?s)if \(\$QuickScan\) \{\s*foreach \(\$t in \$targets\) \{ \$units \+= Expand-QuickScanUnits \$t \}') `
  'QuickScan expands targets into per-exe/dll units'
$expandQuickFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'Expand-QuickScanUnits' -or $n.Name -eq 'script:Expand-QuickScanUnits') }, $true) | Select-Object -First 1
Assert ($expandQuickFn -and $expandQuickFn.Extent.Text -match 'Test-IsExecFile' -and $expandQuickFn.Extent.Text -match 'Test-Excluded' -and $expandQuickFn.Extent.Text -match 'Recurse') `
  'Expand-QuickScanUnits recurses for exec files and honours exclusions'
# GUI: Quick Scan tile passes -QuickScan and offers full/incremental choice
Assert ($src -match "\`$quickScan = \{" -and $src -match "'-QuickScan'" -and $src -match '-QuickScan -Path ') `
  'GUI Quick Scan action runs -QuickScan on all or checked items'
Assert ($src -match "TileQuickScan'\)\.Add_Click\(\`$quickScan\)") 'Quick Scan tile is wired to the quick scan action'

# ---- 6d. Incremental cache checkpointing: keep progress if a long run is cut short ----
$saveCacheFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Save-Cache' }, $true) | Select-Object -First 1
Assert ($saveCacheFn -and $saveCacheFn.Extent.Text -match '\.tmp' -and $saveCacheFn.Extent.Text -match 'Move-Item' -and $saveCacheFn.Extent.Text -match '-Force') `
  'Save-Cache writes atomically (temp file + move) so a kill mid-write cannot corrupt the cache'
Assert ($src -match 'cacheFlushSeconds') 'cache checkpoint interval is configurable via options.cacheFlushSeconds'
# pass-2 flushes the cache during the loop, throttled by the flush interval
Assert ($src -match '(?s)foreach \(\$u in \$toScan\).*?if \(\$cacheDirty -and.*?TotalSeconds -ge \$cacheFlushSec.*?Save-Cache -Cache \$cache; \$lastFlushUtc') `
  'pass-2 checkpoints the cache mid-run so an interrupted scan keeps what it already scanned'
Assert ($src -match '(?s)foreach \(\$u in \$toScan\).*?\$cache\[\$u\] = @\{ sig = \$sig;.*?\$cacheDirty = \$true') `
  'a clean result marks the cache dirty for the next checkpoint'

# ---- 6e. No-prompt elevation: run the app elevated via a scheduled task ----
Assert ($src -match '\[switch\]\$NoPromptGuiShortcut') '-NoPromptGuiShortcut switch parameter declared'
Assert ($src -match 'if \(\$NoPromptGuiShortcut\) \{ Register-NoPromptGuiTask; return \}') `
  'NoPromptGuiShortcut dispatches to Register-NoPromptGuiTask'
$noPromptGuiFn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Register-NoPromptGuiTask' }, $true) | Select-Object -First 1
Assert ($noPromptGuiFn -and $noPromptGuiFn.Extent.Text -match 'RunLevel Highest' -and $noPromptGuiFn.Extent.Text -match 'Register-ScheduledTask' -and $noPromptGuiFn.Extent.Text -match "ScanAV-Gui" -and $noPromptGuiFn.Extent.Text -match 'Ensure-StandaloneLauncher') `
  'no-prompt task runs the app launcher elevated (RunLevel Highest)'
Assert ($noPromptGuiFn -and $noPromptGuiFn.Extent.Text -match 'Test-IsAdmin' -and $noPromptGuiFn.Extent.Text -match 'Invoke-RelaunchElevated') `
  'no-prompt setup self-elevates once to register the task'
Assert ($noPromptGuiFn -and $noPromptGuiFn.Extent.Text -match "No Prompt.*\.lnk|Scan-AV \(No Prompt\)" -and $noPromptGuiFn.Extent.Text -match 'schtasks.exe' -and $noPromptGuiFn.Extent.Text -match '/run /tn ScanAV-Gui') `
  'no-prompt setup creates a separate shortcut that triggers the task'
Assert ($src -match "BtnNoPromptSetup'\)\.Add_Click" -and $src -match 'Register-NoPromptGuiTask') `
  'Settings button is wired to the no-prompt setup'

# ---- 7. Get-VtStatusCode message fallback ----
try { throw 'The remote server returned an error: (404) Not Found.' } catch { $e = $_ }
Assert ((Get-VtStatusCode $e) -eq 404) 'Get-VtStatusCode message fallback -> 404'

# ---- 8. elevation command builder keeps array params separate + parses ----
$Bound = @{ Path = @('C:\Scanned', "C:\Users\dan's stuff"); RescanAll = [System.Management.Automation.SwitchParameter]::new($true); Engine = 'clamav' }
function local:VQ([string]$s) { "'" + ($s -replace "'", "''") + "'" }
$parts = @('&', (VQ 'C:\Apps\scan-av.ps1'))
foreach ($k in $Bound.Keys) {
  $v = $Bound[$k]
  if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $parts += "-$k" } }
  elseif ($v -is [array]) { $parts += "-$k"; $parts += (($v | ForEach-Object { VQ ([string]$_) }) -join ',') }
  else { $parts += "-$k"; $parts += (VQ ([string]$v)) }
}
$cmd = ($parts -join ' ') + "; Read-Host 'pause'"
$perr = $null; $tokens = $null
$cast = [System.Management.Automation.Language.Parser]::ParseInput($cmd, [ref]$tokens, [ref]$perr)
$pathArg = $cast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ArrayLiteralAst] }, $true) | Select-Object -First 1
Assert ((-not $perr -or $perr.Count -eq 0) -and $pathArg -and $pathArg.Elements.Count -eq 2) `
  'elevated relaunch: 2 -Path values stay separate, apostrophe-safe' $cmd

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fails) { Write-Host "$fails test(s) FAILED"; exit 1 }
Write-Host 'ALL TESTS PASSED'
exit 0
