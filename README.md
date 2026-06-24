# avscan

On-demand, scriptable malware scanning for **large game archives and download folders** — the kind of multi-gigabyte `.rar`/`.7z`/`.zip` files that defeat a naive antivirus scan.

Two sibling tools, same workflow:

| Platform | Tool | Engines |
|----------|------|---------|
| Windows | [`windows/scan-av.ps1`](windows/scan-av.ps1) | ClamAV + Emsisoft Emergency Kit |
| macOS / Linux | [`macos/scan-archive`](macos/scan-archive) | ClamAV |

These are **on-demand** scanners — nothing runs in the background. You scan a download once, before you install it.

---

## Why this exists

Pointing `clamscan` (or any AV) straight at a 30 GB game `.rar` mostly **doesn't work**, for two reasons this toolkit handles for you:

1. **ClamAV has a hard 2 GiB-per-file limit.** Modern games ship single asset/data files (`.pak`, `.ucas`, installer `.bin`) far larger than that. ClamAV silently skips them and reports `OK` — a scan that inspected *nothing*. avscan detects these, reports them honestly as **skipped (not clean)**, and focuses the scan on what actually matters.

2. **Malware in a game download lives in the executable surface**, not the multi-GB data blobs. avscan extracts just the `.exe`/`.dll`/script files from an archive with 7-Zip, scans those thoroughly, then cleans up — fast, and it never wastes time on (or falsely clears) the giant data files.

It also knows the difference between a **real detection** and noise:

- ClamAV's `Heuristics.Limits.Exceeded.*` → a size skip, **not** a virus. Reported as skipped.
- A single engine flagging a packed/**Denuvo**-protected game `.exe` (e.g. ClamAV's `Win.Trojan.ZeroCleare` family) is frequently a **false positive**. avscan flags single-engine disagreements and tells you to verify the file's SHA-256 on [VirusTotal](https://www.virustotal.com) before acting — rather than crying wolf.

---

## Windows — `scan-av.ps1`

### Install (one line)

```powershell
powershell -ExecutionPolicy Bypass -File .\scan-av.ps1 -Install
```

This copies the tool into `%LOCALAPPDATA%\ScanAV`, adds it to your PATH (so you can just type `scan-av`), then offers to **auto-download and install the engines**.

### Auto-install the antivirus engines

```powershell
scan-av -InstallEngines
```

Downloads and sets up, with **no admin rights required**:

- **7-Zip** — via `winget` if present, else the official silent installer into a user folder.
- **ClamAV** — the official portable Windows build (latest release from GitHub), into `%LOCALAPPDATA%\ScanAV\engines\ClamAV`, then fetches virus definitions with `freshclam`.
- **Emsisoft Emergency Kit** — downloaded from emsisoft.com, extracted with 7-Zip, then `a2cmd /update` pulls its signatures.

> ⚠️ Several hundred MB of downloads (programs + signature databases). **Emsisoft Emergency Kit is free for private / personal use only.**

If a piece can't be installed automatically (no internet for a step, an interactive extractor, etc.) the tool tells you exactly what to do and where to re-run `scan-av -Configure`.

### First-run configuration

On first run (or `scan-av -Configure`) a wizard:

1. Auto-detects 7-Zip, `clamscan.exe`, `freshclam.exe`, and Emsisoft `a2cmd.exe` (PATH, standard install dirs, the auto-installed copies, and a bounded drive search).
2. Lets you confirm/correct each path (`Enter` = accept, `-` = disable a tool).
3. Asks which **folders** to scan by default.
4. Asks options: exec-only vs. full-archive scan, ClamAV size caps.
5. Saves everything to `%LOCALAPPDATA%\ScanAV\config.json`.

### Daily use

```powershell
scan-av                                # scan all configured folders, both engines
scan-av -Path 'D:\Downloads\Game.rar'  # scan one archive or folder
scan-av -Update                        # refresh ClamAV + Emsisoft definitions first
scan-av -Engine clamav                 # force a single engine (clamav | emsisoft | both)
scan-av -Full                          # extract & scan everything, not just executables
scan-av -Configure                     # re-run setup
```

Per-scan logs land in `%LOCALAPPDATA%\ScanAV\logs`.

### Desktop shortcut & avoiding UAC prompts

`-Install` creates a **Scan-AV** desktop shortcut automatically. It's marked "Run as
administrator" so Emsisoft's `a2cmd` (which self-elevates) prompts **once** at launch
instead of popping a separate elevated console on every scan.

```powershell
scan-av -Shortcut          # (re)create the elevated desktop shortcut
scan-av -NoPromptShortcut  # ZERO prompts: register an elevated scheduled task +
                           # a shortcut that triggers it. Run as Administrator ONCE.
```

`-NoPromptShortcut` is the only way to fully suppress the UAC prompt (UAC can't be
disabled per-app otherwise, and turning UAC off globally is a bad idea). It registers
a Scheduled Task with highest privileges; the desktop shortcut then launches that task,
which runs elevated with no prompt.

---

## macOS / Linux — `scan-archive`

Requires `clamav` and `p7zip` (e.g. `brew install clamav p7zip`).

```bash
cp macos/scan-archive ~/bin/ && chmod +x ~/bin/scan-archive

scan-archive '/path/to/Game.rar'          # scan executable surface of an archive
scan-archive --full '/path/to/Game.7z'    # extract & scan everything
scan-archive --update '/path/to/Game.rar' # freshclam first
scan-archive --keep ...                   # keep the extracted temp folder
```

It lists files over 2 GiB (unscannable), extracts the executable surface, scans with sensible limits, distinguishes real hits from size-skips, and cleans up.

---

## How to read results

| Result | Meaning |
|--------|---------|
| `clean` | No known-malware signature matched the scanned executables. |
| `skipped (>limit)` | A file was too big for ClamAV (>2 GiB) and not scanned — **not** a verdict. |
| One engine flags it | Treat with suspicion **but verify** — packed/Denuvo game exes false-positive often. Check the SHA-256 on VirusTotal. |
| Both engines flag it | High confidence. Don't run it. |

Signature scanning is not proof of safety — for pirated/cracked content especially, a clean result means "no known signature matched." Use VirusTotal for a multi-engine second opinion on anything suspicious.

---

## License

MIT — see [LICENSE](LICENSE). Provided as-is, no warranty. You are responsible for complying with the licenses of ClamAV and Emsisoft Emergency Kit (the latter is free for private use only).
