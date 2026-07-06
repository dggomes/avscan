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

# ---- 2. embedded XAML is well-formed and has the expected controls ----
$src = Get-Content $srcPath -Raw
$m = [regex]::Match($src, '(?s)\$xaml = @"(.*?)\r?\n"@')
Assert $m.Success 'XAML block found'
try {
  $x = [xml]$m.Groups[1].Value
  $names = @($x.SelectNodes('//*') | ForEach-Object { $_.Attributes } | ForEach-Object { $_ } |
             Where-Object { $_ -and $_.LocalName -eq 'Name' } | ForEach-Object { $_.Value })
  foreach ($need in 'BtnAddTop','BtnEdit','SetVtUpload','SetVtKey','SetTimeout','RunResults','RunResultsWrap','HeaderProgress') {
    Assert ($names -contains $need) "XAML control $need present"
  }
} catch { Assert $false 'XAML well-formed' "$_" }

# ---- 3. extract pure functions from the AST ----
foreach ($fnName in @('Get-HitPaths','Get-VtStatusCode','ConvertFrom-ClamBatchLog')) {
  $f = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fnName }, $true) | Select-Object -First 1
  if (-not $f) { Assert $false "function $fnName found"; exit 1 }
  . ([scriptblock]::Create($f.Extent.Text))
}

# ---- 4. Get-HitPaths: ClamAV / Emsisoft / Defender shapes, deduped ----
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
$targets = @('C:\Games\Alpha', 'C:\Games\Alpha Two', 'C:\Downloads\setup.exe')
$lines = @(
  'C:\Games\Alpha\bin\game.exe: OK',
  'C:\Games\Alpha\data\big.bin: Heuristics.Limits.Exceeded.MaxFileSize FOUND',
  'C:\Games\Alpha Two\loader.dll: Win.Trojan.Agent-999 FOUND',
  'C:\Games\Alpha Two\readme.txt: OK',
  "C:\Games\Alpha Two\locked.dat: Can't open file ERROR",
  'C:\Downloads\setup.exe: OK',
  'C:\Elsewhere\stray.exe: OK',
  '----------- SCAN SUMMARY -----------',
  'Scanned files: 5'
)
$map = ConvertFrom-ClamBatchLog -Lines $lines -Targets $targets -Rc 1 -LogFile 'x.log'
$a  = $map['C:\Games\Alpha']; $a2 = $map['C:\Games\Alpha Two']; $d = $map['C:\Downloads\setup.exe']
Assert ($a.Hits.Count -eq 0 -and $a.Skipped -eq 1 -and $a.Scanned -eq '2') 'batch: Alpha gets its skip, no bleed from "Alpha Two"' "hits=$($a.Hits.Count) skip=$($a.Skipped) scanned=$($a.Scanned)"
Assert ($a2.Hits.Count -eq 1 -and $a2.Errors.Count -eq 1 -and $a2.Scanned -eq '2') 'batch: Alpha Two gets its hit + error' "hits=$($a2.Hits.Count) errs=$($a2.Errors.Count) scanned=$($a2.Scanned)"
Assert ($d.Hits.Count -eq 0 -and $d.Scanned -eq '1') 'batch: single-file target attributed' "scanned=$($d.Scanned)"
Assert ($map.Keys.Count -eq 3) 'batch: stray path outside all targets ignored'

# ---- 7. Get-VtStatusCode message fallback ----
try { throw 'The remote server returned an error: (404) Not Found.' } catch { $e = $_ }
Assert ((Get-VtStatusCode $e) -eq 404) 'Get-VtStatusCode message fallback -> 404'

# ---- 8. elevation command builder keeps array params separate + parses ----
$Bound = @{ Path = @('C:\Games', "C:\Users\dan's stuff"); RescanAll = [System.Management.Automation.SwitchParameter]::new($true); Engine = 'clamav' }
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
