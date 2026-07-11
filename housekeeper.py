#!/usr/bin/env python3
"""Mint housekeeper.

Daily (06:00 IST, systemd user timer) health check of this laptop:
  - disk usage on real filesystems (alert at >=85%)
  - failed systemd units, system and user (any = alert)
  - Obsidian vault git drift: uncommitted changes with no snapshot for
    >14 days, or unpushed commits when a remote exists (alert)
  - pending security updates (alert at >=20 — badly behind)
  - pending apt updates + journal errors this boot (context, not alerts)
  - reboot-required flag and battery wear <80% (context, not alerts)

Always sends: a one-line all-clear when every check passes (no API call
needed), a summarized report leading with what to do when something needs
attention (raw findings if the summarizer is unreachable — an alert must
never be lost to an API failure). The ⚠️/✅ icon is the at-a-glance signal.

Failures raise and land in journald:
    journalctl --user -u housekeeper.service -e
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR.parent / "common"))
from agentlib import ask_llm, send_telegram  # noqa: E402

DISK_ALERT_PCT = 85
MOUNTS = ["/", "/home"]
SECURITY_ALERT_COUNT = 20
VAULT_DIR = Path.home() / "Desktop" / "Jayanth-Vault"
VAULT_STALE_DAYS = 14
# Known-benign failed units (casper-md5check: live-USB checksum service,
# always "failed" on installed Mint systems)
IGNORED_UNITS = {"casper-md5check.service"}


def sh(cmd):
    """Run a command, return stdout ('' on any failure — checks degrade gracefully)."""
    try:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        ).stdout.strip()
    except Exception:
        return ""


def check_disks(issues, info):
    seen_devices = set()
    for mount in MOUNTS:
        try:
            dev = os.stat(mount).st_dev
            if dev in seen_devices:  # / and /home on one fs → report once
                continue
            seen_devices.add(dev)
            usage = shutil.disk_usage(mount)
        except OSError:
            continue
        pct = round(usage.used / usage.total * 100)
        line = f"disk {mount}: {pct}% used, {usage.free // 2**30} GiB free"
        (issues if pct >= DISK_ALERT_PCT else info).append(line)


def check_failed_units(issues):
    for scope, cmd in (
        ("system", "systemctl --failed --no-legend --plain"),
        ("user", "systemctl --user --failed --no-legend --plain"),
    ):
        units = [
            l.split()[0]
            for l in sh(cmd).splitlines()
            if l.strip() and l.split()[0] not in IGNORED_UNITS
        ]
        if units:
            issues.append(f"failed {scope} units: {', '.join(units)}")


def check_vault(issues, info):
    """Obsidian vault git drift: notes are only safe if they get committed
    (and pushed, once a remote exists)."""
    if not (VAULT_DIR / ".git").exists():
        return
    git = f"git -C '{VAULT_DIR}'"
    dirty = bool(sh(f"{git} status --porcelain").strip())
    last_ts = sh(f"{git} log -1 --format=%ct")
    days = None
    if last_ts.isdigit():
        days = int((time.time() - int(last_ts)) / 86400)

    if dirty and days is not None and days >= VAULT_STALE_DAYS:
        issues.append(
            f"vault has uncommitted changes and no commit for {days} days "
            f"(cd {VAULT_DIR} && git add -A && git commit)"
        )
    elif dirty:
        age = f"last commit {days}d ago" if days is not None else "no commits yet"
        info.append(f"vault: uncommitted changes ({age})")

    if sh(f"{git} remote").strip():
        ahead = sh(f"{git} rev-list --count @{{u}}..HEAD 2>/dev/null")
        if ahead.isdigit() and int(ahead) > 0:
            issues.append(f"vault: {ahead} commits not pushed to remote")
    else:
        info.append("vault has no git remote — no off-machine backup")


def check_updates(issues, info):
    # package lines look like "name/source version ..."; the header doesn't
    pkgs = [
        l for l in sh("apt list --upgradable 2>/dev/null").splitlines() if "/" in l
    ]
    security = sum("security" in l.lower() for l in pkgs)
    if security >= SECURITY_ALERT_COUNT:
        issues.append(f"{security} SECURITY updates pending (badly behind)")
    elif security > 0:
        info.append(f"{security} security updates pending")
    if pkgs:
        info.append(f"{len(pkgs)} apt packages upgradable total")


def gather_context(info):
    err_count = sh("journalctl -p 3 -b -q --no-pager 2>/dev/null | wc -l")
    if err_count.isdigit() and int(err_count) > 0:
        info.append(f"{err_count} journal error lines this boot")
    if Path("/var/run/reboot-required").exists():
        info.append("reboot required (kernel/libc updated)")


def check_battery(info, base=Path("/sys/class/power_supply")):
    """Note battery wear once it's meaningful (<80% of design capacity).

    Healthy batteries stay silent — a daily 'battery fine' line is noise.
    `base` is parameterized purely for tests (a tmpdir fake sysfs)."""
    for bat in base.glob("BAT*"):
        for prefix in ("energy", "charge"):  # driver exposes one or the other
            try:
                full = int((bat / f"{prefix}_full").read_text())
                design = int((bat / f"{prefix}_full_design").read_text())
            except (OSError, ValueError):
                continue
            if design > 0:
                health = round(full / design * 100)
                if health < 80:
                    info.append(f"battery {bat.name}: {health}% of design capacity")
            break


def main():
    load_dotenv(BASE_DIR / ".env")
    issues, info = [], []

    check_disks(issues, info)
    check_failed_units(issues)
    check_vault(issues, info)
    check_updates(issues, info)
    check_battery(info)
    gather_context(info)

    if not issues:
        notes = "; ".join(info) or "no notes"
        send_telegram(f"🩺✅ Housekeeper\n\nLaptop healthy — all checks passed.\n({notes})")
        return

    findings = "\n".join(f"ALERT: {i}" for i in issues) + "\n" + "\n".join(
        f"note: {i}" for i in info
    )
    try:
        summary = ask_llm(
            "You are a laptop health monitor (Linux Mint). Below are tonight's "
            "findings. Write 2-3 humane, terse sentences: lead with what needs "
            "action and the one command or step to take; mention notes only if "
            "relevant. Plain text.\n\n" + findings,
            max_tokens=300,
        )
    except Exception:
        # An unreachable API must never cost an alert (boot-time runs can
        # beat Wi-Fi) — fall back to the raw findings, unpolished.
        summary = findings
    send_telegram(f"🩺⚠️ Housekeeper\n\n{summary}")


if __name__ == "__main__":
    main()
