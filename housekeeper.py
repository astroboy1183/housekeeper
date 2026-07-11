#!/usr/bin/env python3
"""Mint housekeeper.

Daily (06:00 IST, systemd user timer) health check of this laptop —
comprehensive but root-free; every check degrades gracefully:

  ALERTS (act today)
  - disk usage on real filesystems (>=85%)
  - failed systemd units, system and user (any = alert)
  - housekeeper's OWN timer missing from the schedule
  - fleet watchdog: any cloud agent that did not RUN yesterday (a run
    that never starts alerts nobody else — adopted from the retired
    daily-review agent), and vendored agentlib drift from common/
  - memory pressure (<10% available) or runaway load (>2× cores)
  - CPU package temperature >=85°C
  - kernel storage errors this boot (I/O, ATA, NVMe — a failing disk
    announces itself here long before SMART tools would)
  - Obsidian vault git drift: uncommitted for >14 days, or unpushed
  - pending security updates (>=20 — badly behind)
  - reboot-required ignored for >7 days (tracked in local history)

  NOTES (context, not alarms)
  - security/apt update counts, journal errors this boot, battery wear
    <80%, warm-but-ok temps, swap use, top memory processes
  - 🧹 cleanup ledger: ~/.cache, trash, journald disk usage, autoremove
    candidates — where the gigabytes went
  - repos with uncommitted or unpushed work across ~/agents and ~/Desktop
  - 📈 trend from local history: disk growth vs a week ago

Local memory (state/history.json, gitignored — this agent runs on the
laptop, its memory stays on the laptop): daily disk%, and the first day
reboot-required was seen, so ignoring it for a week escalates.

Always sends: a one-line all-clear when every check passes (no API call
needed), a summarized report leading with what to do when something needs
attention (raw findings if the summarizer is unreachable — an alert must
never be lost to an API failure). The ⚠️/✅ icon is the at-a-glance signal.

Failures raise and land in journald:
    journalctl --user -u housekeeper.service -e
"""

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import date, datetime, timedelta, timezone
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

TEMP_ALERT_C = 85
TEMP_NOTE_C = 70
MEM_AVAILABLE_ALERT_PCT = 10
LOAD_ALERT_FACTOR = 2.0   # load1 above this × cores = something is stuck
SWAP_NOTE_PCT = 50
CACHE_NOTE_GB = 5         # cleanup ledger itemizes past these sizes
TRASH_NOTE_GB = 1
JOURNAL_NOTE_GB = 2
REBOOT_AGE_ALERT_DAYS = 7
DISK_TREND_NOTE_PCT = 5   # grew this much in a week → worth a note
REPO_ROOTS = [Path.home() / "agents", Path.home() / "Desktop"]
REQUIRED_TIMERS = ("housekeeper.timer",)

# The fleet watchdog (adopted from the retired daily-review agent): every
# cloud agent must have actually RUN yesterday. The per-run failure alerts
# only fire when a run starts and dies — a run that never starts alerts
# nobody except this check. (repo, workflow file, label); weeklies carry
# the weekday they fire (0=Mon) and are checked the morning after.
# Fleet paused for credit-saving (Jul 2026): only mail + finance run.
# When re-enabling agents, restore their entries here (see git history).
CLOUD_AGENTS = [
    ("astroboy1183/mail-digest", "mail-digest.yml", "mail"),
    ("astroboy1183/finance-tracker", "finance-tracker.yml", "finance"),
]
WEEKLY_AGENTS = []

# Local memory — deliberately NOT committed anywhere: this agent runs on
# the laptop and its history belongs to the laptop (see .gitignore).
STATE_FILE = BASE_DIR / "state" / "history.json"
HISTORY_DAYS = 60


def sh(cmd):
    """Run a command, return stdout ('' on any failure — checks degrade gracefully)."""
    try:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        ).stdout.strip()
    except Exception:
        return ""


# --- memory (local, gitignored) ------------------------------------------------

def load_history():
    try:
        history = json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=HISTORY_DAYS)).strftime(
        "%Y-%m-%d"
    )
    return {
        k: v for k, v in history.items()
        if k == "reboot_since" or (isinstance(k, str) and k >= cutoff)
    }


def save_history(history):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(history, indent=0, sort_keys=True) + "\n")
    except OSError:
        pass  # memory is a nicety; the report already went out


# --- checks ----------------------------------------------------------------------

def check_disks(issues, info):
    """Returns {mount: pct} for the trend history."""
    seen_devices, pcts = set(), {}
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
        pcts[mount] = pct
        line = f"disk {mount}: {pct}% used, {usage.free // 2**30} GiB free"
        (issues if pct >= DISK_ALERT_PCT else info).append(line)
    return pcts


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


def check_local_timers(issues):
    """The fleet's own local agents must stay scheduled — a watchdog that
    quietly fell off the calendar is the worst kind of dead."""
    listed = sh("systemctl --user list-timers --all --no-legend --plain")
    for timer in REQUIRED_TIMERS:
        if timer not in listed:
            issues.append(
                f"{timer} not scheduled (systemctl --user enable --now {timer})"
            )


def check_memory_load(issues, info, meminfo="/proc/meminfo", loadavg="/proc/loadavg"):
    """Memory pressure, swap use, runaway load, top memory hogs."""
    fields = {}
    try:
        for line in Path(meminfo).read_text().splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts and parts[0].isdigit():
                fields[key] = int(parts[0])  # kB
    except OSError:
        return
    total, avail = fields.get("MemTotal", 0), fields.get("MemAvailable", 0)
    if total:
        avail_pct = round(avail / total * 100)
        if avail_pct < MEM_AVAILABLE_ALERT_PCT:
            top = ", ".join(
                f"{l.split()[0]} {int(l.split()[1]) // 2**20}G"
                for l in sh("ps -eo comm,rss --sort=-rss --no-headers").splitlines()[:3]
                if len(l.split()) == 2 and l.split()[1].isdigit()
            )
            issues.append(
                f"memory pressure: only {avail_pct}% available"
                + (f" (top: {top})" if top else "")
            )
    swap_total, swap_free = fields.get("SwapTotal", 0), fields.get("SwapFree", 0)
    if swap_total:
        used_pct = round((swap_total - swap_free) / swap_total * 100)
        if used_pct >= SWAP_NOTE_PCT:
            info.append(f"swap {used_pct}% used")
    try:
        load1 = float(Path(loadavg).read_text().split()[0])
        cores = os.cpu_count() or 1
        if load1 > LOAD_ALERT_FACTOR * cores:
            issues.append(f"load {load1:.1f} on {cores} cores — something is stuck")
    except (OSError, ValueError, IndexError):
        pass


def check_temps(issues, info, base=Path("/sys/class/thermal")):
    """Hottest thermal zone; sysfs reports millidegrees C."""
    hottest = None
    for zone in base.glob("thermal_zone*"):
        try:
            temp = int((zone / "temp").read_text().strip()) / 1000
        except (OSError, ValueError):
            continue
        if hottest is None or temp > hottest:
            hottest = temp
    if hottest is None:
        return
    if hottest >= TEMP_ALERT_C:
        issues.append(f"CPU at {hottest:.0f}°C at rest — check fans/dust")
    elif hottest >= TEMP_NOTE_C:
        info.append(f"warm: hottest sensor {hottest:.0f}°C")


def check_kernel_errors(issues):
    """Storage errors in this boot's kernel log — a failing disk announces
    itself here long before user-space notices (and without root/SMART)."""
    count = sh(
        "journalctl -k -b -q --no-pager 2>/dev/null | "
        "grep -ciE 'i/o error|ata[0-9.]+: (error|failed)|nvme.*(timeout|reset|error)'"
    )
    if count.isdigit() and int(count) > 0:
        issues.append(
            f"{count} kernel storage error lines this boot — check the disk "
            "(journalctl -k -b | grep -iE 'i/o error|nvme')"
        )


def check_fleet(issues, info, today=None):
    """Did every cloud agent actually run YESTERDAY? Housekeeper fires at
    06:00 — the same minute as the fleet — so today's runs are just
    starting; yesterday is the completed day to judge.

    Uses the laptop's authenticated `gh` CLI. If GitHub is unreachable
    (pre-Wi-Fi boot run), one note is emitted and the check skips — a
    watchdog that cries offline every airplane morning trains you to
    ignore it."""
    today = today or date.today()
    yesterday = (today - timedelta(days=1)).isoformat()
    due = list(CLOUD_AGENTS) + [
        (repo, wf, label)
        for repo, wf, label, weekday in WEEKLY_AGENTS
        if (today - timedelta(days=1)).weekday() == weekday
    ]
    ran, problems = [], []
    for i, (repo, wf, label) in enumerate(due):
        raw = sh(
            f"gh api -X GET repos/{repo}/actions/workflows/{wf}/runs "
            f"-f 'created={yesterday}..{yesterday}' "
            "--jq '[.workflow_runs[] | {event, conclusion}]'"
        )
        if not raw:
            if i == 0:
                info.append("fleet watchdog: gh unreachable — skipped")
                return
            problems.append(f"{label} (query failed)")
            continue
        try:
            runs = json.loads(raw)
        except ValueError:
            problems.append(f"{label} (bad reply)")
            continue
        fired = [r for r in runs if r.get("event") in ("schedule", "workflow_dispatch")]
        ok = [r for r in fired if r.get("conclusion") == "success"]
        if ok:
            ran.append(label)
        elif fired:
            problems.append(f"{label} fired but never succeeded")
        else:
            problems.append(f"{label} DID NOT RUN")
    if problems:
        issues.append(
            f"fleet: {', '.join(problems)} yesterday — check gh run list"
        )
    elif ran:
        info.append(f"fleet: all {len(ran)} cloud agents ran yesterday ✓")


def check_agentlib_drift(issues, base=None):
    """Vendored agentlib copies must stay byte-identical to common/ —
    silent drift means one agent quietly runs different plumbing.
    (Adopted from the retired daily-review agent.)"""
    base = base or Path.home() / "agents"
    try:
        ref = (base / "common" / "agentlib.py").read_bytes()
    except OSError:
        return
    drifted = sorted(
        p.parent.name
        for p in base.glob("*/agentlib.py")
        if p.parent.name != "common" and p.read_bytes() != ref
    )
    if drifted:
        issues.append(f"agentlib drift: {', '.join(drifted)} differ from common/")


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


def check_repo_drift(info):
    """Uncommitted or unpushed work across every repo I keep locally —
    work that exists on one laptop doesn't exist. Notes, not alerts:
    mid-project dirtiness is normal; the vault has its own alert."""
    dirty, unpushed = [], []
    for root in REPO_ROOTS:
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if not (child / ".git").is_dir() or child == VAULT_DIR:
                continue
            git = f"git -C '{child}'"
            if sh(f"{git} status --porcelain").strip():
                dirty.append(child.name)
            ahead = sh(f"{git} rev-list --count @{{u}}..HEAD 2>/dev/null")
            if ahead.isdigit() and int(ahead) > 0:
                unpushed.append(f"{child.name} (+{ahead})")

    def clip(names):
        return ", ".join(names[:4]) + (f" +{len(names) - 4} more" if len(names) > 4 else "")

    if dirty:
        info.append(f"repos with uncommitted work: {clip(dirty)}")
    if unpushed:
        info.append(f"repos with unpushed commits: {clip(unpushed)}")


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


def _du_gb(path):
    out = sh(f"du -s --block-size=1 '{path}' 2>/dev/null")
    head = out.split()[0] if out.split() else ""
    return int(head) / 2**30 if head.isdigit() else 0.0


def check_cleanup(info):
    """🧹 where the gigabytes went — reclaimable space, itemized only when
    it has grown past the thresholds; one quiet summary line otherwise."""
    items = []
    cache = _du_gb(Path.home() / ".cache")
    if cache >= CACHE_NOTE_GB:
        items.append(f"~/.cache {cache:.1f}G (safe to clear)")
    trash = _du_gb(Path.home() / ".local/share/Trash")
    if trash >= TRASH_NOTE_GB:
        items.append(f"trash {trash:.1f}G (empty it)")
    journal = sh("journalctl --disk-usage 2>/dev/null")
    for token in journal.split():
        clean_tok = token.rstrip(".").rstrip(",")
        if clean_tok.endswith("G") and clean_tok[:-1].replace(".", "").isdigit():
            if float(clean_tok[:-1]) >= JOURNAL_NOTE_GB:
                items.append(
                    f"journald {clean_tok} (sudo journalctl --vacuum-size=500M)"
                )
            break
    autoremove = sh("apt-get -s autoremove 2>/dev/null | grep -c '^Remv'")
    if autoremove.isdigit() and int(autoremove) > 0:
        items.append(f"{autoremove} packages autoremovable (sudo apt autoremove)")
    if items:
        info.append("🧹 cleanup: " + " · ".join(items))


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


def gather_context(info):
    err_count = sh("journalctl -p 3 -b -q --no-pager 2>/dev/null | wc -l")
    if err_count.isdigit() and int(err_count) > 0:
        info.append(f"{err_count} journal error lines this boot")


def apply_trends(issues, info, history, root_pct, reboot_needed, today=None):
    """The history-powered checks: disk growth vs a week ago, and a
    reboot-required flag that has been ignored long enough to escalate.
    Mutates `history` in place with today's facts."""
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if reboot_needed:
        since = history.get("reboot_since") or today
        history["reboot_since"] = since
        age = (
            datetime.strptime(today, "%Y-%m-%d")
            - datetime.strptime(since, "%Y-%m-%d")
        ).days
        if age >= REBOOT_AGE_ALERT_DAYS:
            issues.append(
                f"reboot required, ignored for {age} days (kernel/libc updated)"
            )
        else:
            info.append("reboot required (kernel/libc updated)")
    else:
        history.pop("reboot_since", None)

    if root_pct is not None:
        week_ago = (
            datetime.strptime(today, "%Y-%m-%d") - timedelta(days=7)
        ).strftime("%Y-%m-%d")
        past = [
            v.get("disk") for k, v in history.items()
            if k != "reboot_since" and k <= week_ago and isinstance(v, dict)
        ]
        baseline = past[-1] if past else None
        if baseline is not None and root_pct - baseline >= DISK_TREND_NOTE_PCT:
            info.append(f"📈 disk grew {root_pct - baseline}% in a week "
                        f"({baseline}% → {root_pct}%)")
        history[today] = {"disk": root_pct}


def main():
    load_dotenv(BASE_DIR / ".env")
    issues, info = [], []

    pcts = check_disks(issues, info)
    check_failed_units(issues)
    check_local_timers(issues)
    check_fleet(issues, info)
    check_agentlib_drift(issues)
    check_memory_load(issues, info)
    check_temps(issues, info)
    check_kernel_errors(issues)
    check_vault(issues, info)
    check_repo_drift(info)
    check_updates(issues, info)
    check_cleanup(info)
    check_battery(info)
    gather_context(info)

    history = load_history()
    apply_trends(
        issues, info, history,
        pcts.get("/"), Path("/var/run/reboot-required").exists(),
    )

    if not issues:
        notes = "\n".join(f"• {i}" for i in info) or "• no notes"
        send_telegram(
            "🩺✅ Housekeeper\n\nLaptop healthy — all checks passed.\n" + notes
        )
        save_history(history)
        return

    findings = "\n".join(f"ALERT: {i}" for i in issues) + "\n" + "\n".join(
        f"note: {i}" for i in info
    )
    try:
        summary = ask_llm(
            "You are a laptop health monitor (Linux Mint). Below are today's "
            "findings. Write 2-4 humane, terse sentences: lead with what needs "
            "action and the one command or step to take for each ALERT; mention "
            "notes only if relevant. Plain text.\n\n" + findings,
            max_tokens=400,
        )
    except Exception:
        # An unreachable API must never cost an alert (boot-time runs can
        # beat Wi-Fi) — fall back to the raw findings, unpolished.
        summary = findings
    send_telegram(f"🩺⚠️ Housekeeper\n\n{summary}")
    save_history(history)


if __name__ == "__main__":
    main()
