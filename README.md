# avscan

**On-demand, multi-engine malware scanning for Windows** — scan folders, downloads, and large archives with up to three engines (ClamAV, Emsisoft, Microsoft Defender), working around the file-size limits that make a naive antivirus scan miss things.

It is **on-demand**: nothing runs in the background. You scan something once, when you choose to.

---

## Why it exists

Pointing a signature scanner straight at a large archive (a multi-gigabyte `.rar`/`.7z`/`.zip`) often **doesn't do what you expect**, for two reasons this tool handles for you:

1. **ClamAV has a hard 2 GiB-per-file limit.** Large downloads frequently contain single data files bigger than that. ClamAV silently skips them and reports `OK` — a scan that inspected *nothing*. avscan detects these, reports them honestly as **skipped (not clean)**, and focuses the scan on the parts that matter.

2. **Executable code is the real risk surface**, not the large opaque data blobs. avscan extracts just the executable/script files (`.exe`, `.dll`, installers, scripts) from an archive with 7-Zip, scans those thoroughly, then cleans up — fast, and it never wastes time on (or falsely clears) the large data files.

It also distinguishes a **real detection** from noise:

- ClamAV's `Heuristics.Limits.Exceeded.*` is a **size skip, not a virus**.
- A single engine flagging a **packed/obfuscated** executable is frequently a false positive. avscan flags single-engine disagreements and suggests verifying the file's SHA-256 on a multi-engine service before acting, rather than crying wolf.

---

## Components

| Platform | Tool | Engines |
|----------|------|---------|
| Windows | [`windows/scan-av.ps1`](windows/scan-av.ps1) | ClamAV + Emsisoft Emergency Kit + Microsoft Defender |
| macOS / Linux | [`macos/scan-archive`](macos/scan-archive) | ClamAV |

Each engine is independently toggleable in **Settings**. Optionally, ClamAV can pull
**third-party (SaneSecurity) signatures**, and when a **VirusTotal** API key is
configured the SHA-256 of any flagged file is checked against VirusTotal's
multi-engine database automatically — deduplicated, cached for 7 days, and
throttled to the free tier's 4 requests/minute. Two further VT options:

- **Per-folder "VT: all files" mode** — the VT badge on each folder card switches
  that folder to also reputation-check **all new/changed executables** against
  VirusTotal on every scan, even when the local engines find nothing (catches
  fresh malware that signatures miss; ≥3 VT engines flagging counts as a
  detection). Default is flagged-files-only. `-VtAll` forces it for one CLI run.
- **Upload unknown files** (opt-in, Settings) — files VirusTotal has never seen
  are submitted for a full multi-engine analysis (max 650 MB; uploads are shared
  with the VT community, so never enable it for folders holding private files).

The Windows tool is both a **command-line scanner** and a **touch/controller-friendly desktop app** (WPF). The macOS/Linux tool is a small command-line script.

---

## Windows

### Install

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\scan-av.ps1 -Install
```

This copies the tool into `%LOCALAPPDATA%\ScanAV`, adds it to your PATH, creates a desktop shortcut, and offers to **auto-download the engines** (no admin required):

- **7-Zip** — via `winget` if present, else the official installer into a user folder.
- **ClamAV** — the official portable Windows build, then `freshclam` for the database.
- **Emsisoft Emergency Kit** — downloaded and extracted, then `a2cmd /update` for its database.

> Downloads total several hundred MB (programs + signature databases). See **Attribution** for engine licensing.

### The app

Launching the **Scan-AV** desktop shortcut opens a dark, touch-first dashboard:

- A protection-status hero and a prominent **Scan Now** action.
- **Scan Targets** as expandable cards with large checkboxes — pick whole folders or specific sub-folders; give folders custom display names.
- Folder cards include quick actions to open in Explorer, move/rename into another configured scan folder, or edit the display label.
- Action tiles: Scan All, Scan Checked, Update Definitions, Update App, View Logs, Add Folder.
- Pages in a left nav rail: **Dashboard / Scan / Updates / Logs / Settings / About**. Scans run in-app and keep running when you switch pages; a header progress bar shows activity.
- Clean scan results show next-step cards: open the item, move/rename it into the Games folder, choose an installer to run, or launch it with Windows' **System (Enhanced)** high-DPI compatibility override.
- In-app **Settings** (engines, third-party signatures, VirusTotal API key, scan mode, size limits, auto-update, incremental) and a **log browser**.
- Header controls can hide the app to the tray or exit it explicitly; the tray menu can reopen or exit the app.

The installer also creates `%LOCALAPPDATA%\ScanAV\ScanAV.exe`, a small standalone
launcher for the desktop app. If you use a launcher such as ROG Armoury, point it
at that EXE instead of the PowerShell script; app updates refresh it automatically.
The normal desktop shortcut targets this EXE directly. The optional zero-prompt
shortcut still targets the Windows scheduled task runner by design.

```powershell
scan-av -Gui          # open the app from the command line
scan-av -SelfUpdate   # update to the latest version from GitHub
```

### Command line

```powershell
scan-av                                 # scan configured folders, both engines
scan-av -Path 'D:\Downloads\file.rar'   # scan one archive or folder
scan-av -Update                         # force a definition refresh
scan-av -RescanAll                      # ignore the cache and re-scan everything
scan-av -VtAll                          # also VT-check new executables this run
scan-av -Engine all                     # ClamAV + Emsisoft + Defender
scan-av -Configure                      # re-run setup
scan-av -AddFolder 'D:\Stuff'           # manage the saved folder list
scan-av -InstallContextMenu             # right-click "Antivirus Scan" (folders + files)
scan-av -ListQuarantine                 # list quarantined files
scan-av -RestoreQuarantine <name|all>   # restore from quarantine
```

Exit codes: `0` clean, `1` threats found, `2` some items could not be scanned.

### Behavior

- **Incremental scanning** — a cache (`%LOCALAPPDATA%\ScanAV\scan-cache.json`) records what has been scanned; unchanged items are skipped on later runs. Change is detected by size + modified-time (no re-hashing). `-RescanAll` forces a full re-scan. Items whose scan **failed** (engine error, encrypted/corrupt archive) are never cached as clean — they are reported and retried on the next run.
- **Move-aware** — an item scanned clean and then **moved (or copied) to another watched folder is not re-scanned**: a clean cache entry with the same name and identical content signature (file count + total size + newest modified-time) is recognised as the same content at a new path and migrated. Renamed or modified items still re-scan.
- **Batched ClamAV** — all in-place items in a run are scanned in **one** clamscan invocation, so the multi-second signature-database load happens once instead of once per folder. Results are attributed back per item, so incremental caching still works per folder.
- **Engine timeout** — a stuck engine is killed after a configurable timeout (default 30 min) and the item is reported as *not scanned*, never as clean.
- **Quarantine** — flagged files (or the archive containing them) can be moved to `%LOCALAPPDATA%\ScanAV\quarantine`, renamed so they can't run, and restored later (`-ListQuarantine` / `-RestoreQuarantine`, or the Quarantine button on a threat card in the app).
- **Auto-update** — definitions refresh before a scan if older than a configurable interval.
- **Explorer right-click** — a per-user "Antivirus Scan" entry on folders **and on archive/executable files** runs an elevated scan of just that item (on Windows 11 it's under "Show more options").
- **In-app results** — the Scan page shows a real per-item progress bar and, when threats are found, result cards with *Open VirusTotal / Show in Explorer / Quarantine* actions; a tray notification fires when a scan finishes.
- Per-scan logs are kept in `%LOCALAPPDATA%\ScanAV\logs` (pruned after 7 days).

---

## macOS / Linux

Requires `clamav` and `p7zip` (e.g. `brew install clamav p7zip`).

```bash
cp macos/scan-archive ~/bin/ && chmod +x ~/bin/scan-archive
scan-archive '/path/to/file.rar'          # scan the executable surface of an archive
scan-archive --full '/path/to/file.7z'    # extract & scan everything
scan-archive --update '/path/to/file.rar' # freshclam first
VT_API_KEY=... scan-archive 'file.rar'    # + VirusTotal hash lookup on detections
```

---

## How to read results

| Result | Meaning |
|--------|---------|
| `clean` | No known-malware signature matched the scanned files. |
| `skipped (>limit)` | A file was too large for ClamAV (>2 GiB) and not scanned — **not** a verdict. |
| One engine flags it | Treat with suspicion **but verify** — packed/obfuscated executables can false-positive. Check the file's SHA-256 on a multi-engine service. |
| Both engines flag it | High confidence. Don't run it. |

Signature scanning is **not proof of safety**. A clean result means "no known signature matched." For anything from an untrusted source, get a multi-engine second opinion.

---

## Attribution

This project is a wrapper/UI around third-party scanning engines and tools. It does not include their code; it downloads and invokes the official builds. All credit for the actual detection belongs to them.

- **ClamAV** — open-source antivirus engine by **Cisco Talos**. Licensed under **GPLv2**. <https://www.clamav.net>
- **Emsisoft Emergency Kit** (`a2cmd` command-line scanner) — by **Emsisoft**. **Free for private/personal use only**; commercial use requires a license. <https://www.emsisoft.com/en/emergency-kit/>
- **Microsoft Defender** (`MpCmdRun.exe`) — the antivirus engine built into Windows; invoked in report-only mode. <https://www.microsoft.com>
- **SaneSecurity** — optional third-party ClamAV signature databases. <https://sanesecurity.com>
- **VirusTotal** — optional multi-engine hash lookup (requires a free API key, set in Settings). <https://www.virustotal.com>
- **7-Zip** — by **Igor Pavlov**. Used for archive inspection/extraction. <https://www.7-zip.org>

Built with **PowerShell** and **WPF** (Windows) / Bash (macOS/Linux). You are responsible for complying with each engine's license, especially Emsisoft's private-use terms.

---

## License

MIT — see [LICENSE](LICENSE). Provided as-is, without warranty. This is a convenience tool, not a substitute for a maintained, always-on security solution.
