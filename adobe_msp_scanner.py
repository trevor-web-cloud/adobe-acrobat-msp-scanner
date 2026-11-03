#!/usr/bin/env python3
"""
Adobe Acrobat MSP update scanner.

Catches Acrobat MSP updates that Adobe has placed on its download servers
(ardownload*.adobe.com) but not yet announced on its web pages.

Strategy:
  1. Probe FORWARD ONLY from the last confirmed build number -- no historical
     re-scanning. Probe window = (persisted server-verified latest build + 1)
     up to max(persisted build, latest announced build on the official
     Release Notes page) + DAILY_LOOKAHEAD. The announced version itself is
     always probed, never skipped.
  2. Persist the high-water mark: every run reads
     ~/workspace/file-monitor/adobe-msp-scan-state.json, probes forward, and
     writes back the newest CONFIRMED build, so the next run continues there.
  3. Branch continuation (DC track): build numbers run continuously across
     branch changes (e.g. 26.001.21789 -> 26.002.21869), so the build number
     is the primary anchor and the branch (26.002, 26.003, 26.004, ...) is
     a candidate list. Each build in the window is probed against two
     candidate branches -- the current (announced/persisted) branch and the
     next branch in the same year -- so an in-year branch rollover
     (announced or not) is picked up automatically with no manual config
     change. A year rollover (27.001) is adopted once Release Notes
     announces it, via the announced-branch candidate.

URL pattern:
  https://<host>/pub/adobe/acrobat/win/<dir>/<full_ver>/<file_prefix><full_ver>.msp
  where full_ver = <branch digits><build>, e.g. branch 26002 + build 22031.

Release Notes anchor:
  https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html
  Masked entries (e.g. "26.002.2xxxx") carry no usable build number and are
  ignored as anchors.

Usage:
    python3 adobe_msp_scanner.py init    # one-time full-range bootstrap
    python3 adobe_msp_scanner.py daily   # forward-only incremental scan

Only HEAD requests are made; nothing is downloaded.
"""

import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.path.expanduser("~/workspace/file-monitor")
STATE_PATH = os.path.join(BASE_DIR, "adobe-msp-scan-state.json")

HOSTS = ["https://ardownload3.adobe.com", "https://ardownload2.adobe.com"]
RELEASE_NOTES_URL = ("https://www.adobe.com/devnet-docs/acrobatetk/tools/"
                     "ReleaseNotesDC/index.html")

PRODUCTS = {
    "classic_x64": {
        "label": "Acrobat Classic x64",
        "dir": "AcrobatClassic",
        "file_prefix": "AcrobatClassicx64Upd",
        "ver_prefix": "24001",      # display branch "24.001."
        "multi_branch": False,
        "rn_branch": "24.001.",     # branch prefix on the Release Notes page
        "start_num": 30300,
        "scan_range": 500,
    },
    "dc_x64": {
        "label": "Acrobat DC x64",
        "dir": "AcrobatDC",
        "file_prefix": "AcrobatDCx64Upd",
        "ver_prefix": "26002",      # branch the persisted state starts on
        "multi_branch": True,       # build numbers continue across branches
        "rn_year_min": 25,          # Release Notes: DC track = year >= 25
        "start_num": 21800,
        "scan_range": 500,
    },
    "dc_x86": {
        "label": "Acrobat DC x86",
        "dir": "AcrobatDC",
        "file_prefix": "AcrobatDCUpd",
        "ver_prefix": "26002",
        "multi_branch": True,
        "rn_year_min": 25,
        "start_num": 21800,
        "scan_range": 500,
    },
}

WORKERS = 16
TIMEOUT = 12
DAILY_LOOKAHEAD = 150   # how far above the anchor build to probe each run
EXTEND_CHUNK = 200      # init-mode upward extension chunk size
EXTEND_MAX = 2000       # init-mode upward extension cap

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


# --------------------------------------------------------------------------
# Version helpers. A full version is <branch digits><build>:
# branch digits "26002" + build 22031 -> full "2600222031" -> "26.002.22031".
# --------------------------------------------------------------------------

def display_of(branch_digits, build):
    return "{}.{}.{}".format(branch_digits[:2], branch_digits[2:], build)


def display_version(full_ver):
    return "{}.{}.{}".format(full_ver[:2], full_ver[2:5], full_ver[5:])


def build_num(display):
    # "24.001.30383" -> 30383
    return int(display.split(".")[2])


def branch_digits_of(display):
    # "26.003.22150" -> "26003"
    yy, bbb, _ = display.split(".")
    return yy + bbb


def parse_branch(digits):
    return int(digits[:2]), int(digits[2:])


def succ_branch(digits):
    yy, bbb = parse_branch(digits)
    return "{}{:03d}".format(yy, bbb + 1)


def next_year_branch(digits):
    yy, _ = parse_branch(digits)
    return "{:02d}001".format(yy + 1)


def candidate_branches(persisted_branch, rn_branch):
    """Ordered branch candidates for probing (most likely first):
    announced branch, persisted branch, any same-year branches between
    them, and the next branch in the same year. Two candidates in the
    steady state (e.g. 26002, 26003), so 26.002 -> 26.003 -> 26.004 ->
    26.005 continues automatically. (Per user decision 2026-10-27, the
    speculative next-year branch such as 27001 is NOT probed; a year
    rollover surfaces via the announced branch once Release Notes lists
    it, and the in-between logic then covers it.)
    """
    cands = []

    def add(b):
        if b and b not in cands:
            cands.append(b)

    add(rn_branch)
    add(persisted_branch)
    if persisted_branch and rn_branch:
        py, pb = parse_branch(persisted_branch)
        ry, rb = parse_branch(rn_branch)
        if py == ry and rb > pb:
            cur = persisted_branch
            while parse_branch(cur)[1] < rb:
                cur = succ_branch(cur)
                add(cur)
    known = [b for b in (persisted_branch, rn_branch) if b]
    if known:
        hi = max(known, key=lambda b: parse_branch(b))
        add(succ_branch(hi))
    return cands


# --------------------------------------------------------------------------
# Probing (HEAD only). A 404 means "not published yet"; a network-level
# failure is inconclusive and reported separately via `responded`.
# --------------------------------------------------------------------------

def probe(build, product, branch_digits):
    """HEAD-probe one (branch, build). Returns (info_or_None, responded)."""
    full_ver = "{}{}".format(branch_digits, build)
    responded = False
    for host in random.sample(HOSTS, len(HOSTS)):
        url = ("{}/pub/adobe/acrobat/win/{}/{}/{}{}.msp".format(
            host, product["dir"], full_ver, product["file_prefix"], full_ver))
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                responded = True
                if 200 <= resp.status < 300:
                    size = resp.headers.get("Content-Length")
                    return ({
                        "num": build,
                        "branch": branch_digits,
                        "version": full_ver,
                        "display": display_of(branch_digits, build),
                        "size": int(size) if size and size.isdigit() else None,
                        "url": url,
                    }, True)
                return (None, True)
        except urllib.error.HTTPError as e:
            responded = True
            if e.code in (404, 410):
                return (None, True)
            # other HTTP errors: try the other host
        except Exception:
            pass  # try the other host
    return (None, responded)


def scan_window(builds, product, branches):
    """Probe each build against the candidate branches (in order, first hit
    wins). Returns ({build: info}, responded_build_count)."""
    valid = {}
    responded = 0

    def _probe_build(b):
        any_resp = False
        for br in branches:
            info, resp = probe(b, product, br)
            any_resp = any_resp or resp
            if info:
                return (b, info, any_resp)
        return (b, None, any_resp)

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for b, info, ok in ex.map(_probe_build, builds):
            if ok:
                responded += 1
            if info:
                valid[b] = info
    return valid, responded


# --------------------------------------------------------------------------
# Release Notes anchor (via curl: adobe.com blocks Python's TLS fingerprint
# and spoofed browser User-Agents; curl's default UA passes).
# --------------------------------------------------------------------------

def fetch_url_curl(url):
    try:
        out = subprocess.run(
            ["curl", "-sL", "--max-time", "25", url],
            capture_output=True, timeout=40)
        if out.returncode == 0 and out.stdout:
            return out.stdout.decode("utf-8", errors="ignore")
    except Exception:
        pass
    return None


def fetch_release_notes_latest():
    """Return {product_key: {"build", "display", "branch"} or None} with the
    latest ANNOUNCED build per product, or None on fetch/parse failure.

    A response counts only if it contains real version numbers (a 403 block
    page does not). Masked versions like "26.002.2xxxx" never match the
    pattern, so they are never used as anchors. Failure is non-fatal: the
    persisted state file remains the primary anchor.
    """
    result = {k: None for k in PRODUCTS}
    html = None
    for attempt in (1, 2):
        html = fetch_url_curl(RELEASE_NOTES_URL)
        if html and re.search(r"[0-9]{2}\.[0-9]{3}\.[0-9]{5}", html):
            break
        html = None
        if attempt == 1:
            time.sleep(45)
    if not html:
        return result
    versions = re.findall(r"[0-9]{2}\.[0-9]{3}\.[0-9]{5}", html)
    for key, product in PRODUCTS.items():
        if product.get("multi_branch"):
            pool = [v for v in versions
                    if int(v.split(".")[0]) >= product["rn_year_min"]]
        else:
            pool = [v for v in versions if v.startswith(product["rn_branch"])]
        if not pool:
            continue
        latest = max(pool, key=lambda v: tuple(map(int, v.split("."))))
        result[key] = {
            "build": build_num(latest),
            "display": latest,
            "branch": branch_digits_of(latest),
        }
    return result


# --------------------------------------------------------------------------
# State: the persisted high-water mark (server-verified builds only).
# --------------------------------------------------------------------------

def load_state():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    return {"products": {}}


def save_state(state):
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, STATE_PATH)


def persisted_of(ps, product):
    """(build, branch) from state, with fallback to the legacy fields."""
    build = ps.get("latest_build", ps.get("latest_num"))
    branch = ps.get("latest_branch", product["ver_prefix"])
    return build, branch


def record_latest(ps, product, info):
    ps.update({
        "label": product["label"],
        "dir": product["dir"],
        "file_prefix": product["file_prefix"],
        "ver_prefix": info["branch"],
        "latest_num": info["num"],
        "latest_build": info["num"],
        "latest_branch": info["branch"],
        "latest_display": info["display"],
    })
    return ps


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------

def do_init():
    """One-time bootstrap: scan the configured historical range on the
    configured branch, then extend upward while the top stays live, to
    establish the high-water mark."""
    state = {"products": {}}
    summary = {}
    for key, product in PRODUCTS.items():
        branch = product["ver_prefix"]
        start, rng = product["start_num"], product["scan_range"]
        top = start + rng
        valid, responded = scan_window(list(range(start, top + 1)),
                                       product, [branch])
        probed = rng + 1

        extended = 0
        while valid and max(valid) >= top and extended < EXTEND_MAX:
            chunk = list(range(top + 1, top + EXTEND_CHUNK + 1))
            cvalid, cresp = scan_window(chunk, product, [branch])
            responded += cresp
            probed += len(chunk)
            if not cvalid:
                break
            valid.update(cvalid)
            top += EXTEND_CHUNK
            extended += EXTEND_CHUNK

        ps = {"start_num": start, "scan_range": rng}
        latest_info = valid[max(valid)] if valid else None
        if latest_info:
            ps = record_latest(ps, product, latest_info)
        else:
            ps.update({"label": product["label"], "dir": product["dir"],
                       "file_prefix": product["file_prefix"],
                       "ver_prefix": branch, "latest_num": None,
                       "latest_build": None, "latest_branch": branch,
                       "latest_display": None})
        state["products"][key] = ps
        summary[key] = {
            "label": product["label"],
            "probed": probed,
            "responded": responded,
            "valid_count": len(valid),
            "latest_display": ps["latest_display"],
            "latest_size": latest_info["size"] if latest_info else None,
        }
    save_state(state)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


def do_daily():
    """Forward-only scan with automatic branch continuation (see module
    docstring). the Release Notes anchor extends the window but never skips
    an announced build; only server-confirmed builds are written back."""
    state = load_state()
    rn_latest = fetch_release_notes_latest()
    report = {"checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "anchor": {}, "new": {}, "anomalies": []}

    for key, product in PRODUCTS.items():
        ps = state["products"].get(key, {})
        persisted_build, persisted_branch = persisted_of(ps, product)
        rn = rn_latest.get(key)

        if not product.get("multi_branch"):
            # Classic: single fixed branch; an announced branch change still
            # needs a human to confirm the new track.
            if rn and rn["branch"] != persisted_branch:
                report["anomalies"].append(
                    "{}: Release Notes now announces {}; the version branch "
                    "appears to have changed".format(
                        product["label"], rn["display"])
                    + " (currently probing prefix {}). Please confirm "
                      "manually whether the scan configuration needs "
                      "updating.".format(persisted_branch))
                continue
            branches = [persisted_branch]
        else:
            branches = candidate_branches(
                persisted_branch, rn["branch"] if rn else None)

        if persisted_build is None and rn is None:
            report["anomalies"].append(
                "{}: no baseline version (neither the state file nor "
                "Release Notes has data)".format(product["label"])
                + ". Run init mode first to establish a baseline.")
            continue

        if persisted_build is None:
            # No server-verified baseline: probe the announced build itself
            # plus forward (it may not be on the server yet).
            probe_start = rn["build"]
            probe_end = rn["build"] + DAILY_LOOKAHEAD
        else:
            probe_start = persisted_build + 1
            probe_end = (max(persisted_build, rn["build"] if rn else persisted_build)
                         + DAILY_LOOKAHEAD)

        report["anchor"][key] = {
            "label": product["label"],
            "persisted_latest": (display_of(persisted_branch, persisted_build)
                                 if persisted_build is not None else None),
            "release_notes_latest": rn["display"] if rn else None,
            "probe_range": [probe_start, probe_end],
            "branches": branches,
        }

        builds = list(range(probe_start, probe_end + 1))
        valid, responded = scan_window(builds, product, branches)

        if responded == 0:
            report["anomalies"].append(
                "{}: all {} probe requests went unanswered; the download "
                "hosts may be unreachable.".format(
                    product["label"], len(builds)))
            continue

        new_infos = sorted(
            (info for b, info in valid.items()
             if persisted_build is None or b > persisted_build),
            key=lambda i: i["num"])
        if new_infos:
            top_info = valid[max(valid)]
            state["products"][key] = record_latest(ps, product, top_info)
            report["new"][key] = {
                "label": product["label"],
                "versions": new_infos,
            }

    save_state(state)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "daily"
    os.makedirs(BASE_DIR, exist_ok=True)
    if mode == "init":
        do_init()
    else:
        do_daily()
