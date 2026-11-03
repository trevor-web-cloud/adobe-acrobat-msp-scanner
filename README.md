# Adobe Acrobat MSP Scanner

A small Python tool that detects Adobe Acrobat `.msp` update files after they appear on Adobe's download servers (`ardownload2.adobe.com` / `ardownload3.adobe.com`) but before they are announced on Adobe's Release Notes page.

It only sends HTTP `HEAD` requests. It never downloads an update file.

## What it tracks

| Product | Directory | File prefix |
|---|---|---|
| Acrobat Classic x64 | `AcrobatClassic` | `AcrobatClassicx64Upd` |
| Acrobat DC x64 | `AcrobatDC` | `AcrobatDCx64Upd` |
| Acrobat DC x86 | `AcrobatDC` | `AcrobatDCUpd` |

## How it works

- **Forward-only probing:** each run starts from the latest server-verified build stored in the state file, then probes forward up to `max(persisted build, latest announced build) + 150`.
- **Release Notes anchor:** the official Release Notes page is used only to extend the probe window. An announced build is always probed and is never skipped.
- **Automatic branch continuation (DC track):** build numbers continue across branch changes, so each build is probed against two candidate branches: the current branch and the next branch in the same year. For example, `26.002 -> 26.003 -> 26.004 -> 26.005` continues without manual configuration changes.
- **Verified state only:** only builds confirmed by the download server are written back to the state file. A `404` means "not published yet"; a timeout or connection failure is treated as inconclusive.
- **Anomaly reporting:** the JSON report flags unreachable hosts, a suspected Classic branch change, or a missing baseline.

## Requirements

- Python 3
- `curl` available on the system path

The scanner uses only the Python standard library. The Release Notes page is fetched through `curl` because Adobe's site may reject Python's TLS fingerprint or spoofed browser user agents.

## Usage

Create the initial baseline by scanning the configured historical range:

```bash
python3 adobe_msp_scanner.py init
```

Run a forward-only daily scan:

```bash
python3 adobe_msp_scanner.py daily
```

The daily scan prints a JSON report containing the probe anchors, any newly found versions, and any anomalies.

## State file

By default, the scanner reads and writes:

```text
~/workspace/file-monitor/adobe-msp-scan-state.json
```

To use a different location, edit `BASE_DIR` and `STATE_PATH` in `adobe_msp_scanner.py`.

## Notes

- Masked Release Notes entries such as `26.002.2xxxx` do not provide a usable build number and are ignored as anchors.
- A year rollover such as `27.001` is adopted after it appears in Release Notes through the announced-branch candidate.
- No license has been specified for this repository yet.
