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
multi-engine database automatically.

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
- Action tiles: Scan All, Scan Checked, Update Definitions, Update App, View Logs, Add Folder.
- Pages in a left nav rail: **Dashboard / Scan / Updates / Logs / Settings / About**. Scans run in-app and keep running when you switch pages; a header progress bar shows activity.
- In-app **Settings** (engines, third-party signatures, VirusTotal API key, scan mode, size limits, auto-update, incremental) and a **log browser**.

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
scan-av -Configure                      # re-run setup
scan-av -AddFolder 'D:\Stuff'           # manage the saved folder list
scan-av -InstallContextMenu             # add a folder right-click "Antivirus Scan"
```

### Behavior

- **Incremental scanning** — a cache (`%LOCALAPPDATA%\ScanAV\scan-cache.json`) records what has been scanned; unchanged items are skipped on later runs. Change is detected by size + modified-time (no re-hashing). `-RescanAll` forces a full re-scan.
- **Auto-update** — definitions refresh before a scan if older than a configurable interval.
- **Explorer right-click** — a per-user "Antivirus Scan" entry on folders runs an elevated scan of just that folder (on Windows 11 it's under "Show more options").
- Per-scan logs are kept in `%LOCALAPPDATA%\ScanAV\logs` (pruned after 7 days).

---

## macOS / Linux

Requires `clamav` and `p7zip` (e.g. `brew install clamav p7zip`).

```bash
cp macos/scan-archive ~/bin/ && chmod +x ~/bin/scan-archive
scan-archive '/path/to/file.rar'          # scan the executable surface of an archive
scan-archive --full '/path/to/file.7z'    # extract & scan everything
scan-archive --update '/path/to/file.rar' # freshclam first
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
