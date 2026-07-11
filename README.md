# housekeeper

Daily laptop health check → Telegram, 06:00 IST via a systemd **user
timer**. A local agent: the code lives in this repo (cloned into the
fleet Codespace for editing/backup), but it *runs* only on the laptop it
checks. One agent, one task, one bot: `@jayanth_laptop_alerts_bot` — a
message from this bot means *act now* (or a ✅ all-clear).

## What it checks

| Check | Alert when | Otherwise |
|---|---|---|
| Disk usage (`/`, `/home`) | ≥ 85% used | free-space note |
| Failed systemd units (system + user) | any (minus known-benign) | — |
| Obsidian vault git drift | dirty ≥ 14 days, or unpushed commits | dirty note |
| Pending security updates | ≥ 20 (badly behind) | count note |
| Journal errors this boot | — | count note |
| Reboot-required flag | — | note when present |
| Battery wear | — | note when < 80% of design |

## How the code works

`housekeeper.py`, in pipeline order:

- **`sh(cmd)`** — runs a shell command, returns stdout or `''` on ANY
  failure: every check degrades gracefully instead of crashing the run.
- **`check_disks(issues, info)`** — `shutil.disk_usage` per mount;
  deduped by `st_dev` so `/` and `/home` on one filesystem report once.
  Lines land in `issues` (≥ 85%) or `info`.
- **`check_failed_units(issues)`** — `systemctl --failed` for both
  system and user scopes, minus `IGNORED_UNITS` (casper-md5check is
  always "failed" on installed Mint).
- **`check_vault(issues, info)`** — notes are only safe when committed
  and pushed: alerts on dirty-with-no-commit-for-14-days and on
  unpushed commits; notes a missing remote (no off-machine backup).
- **`check_updates(issues, info)`** — parses `apt list --upgradable`
  once in Python; ≥ 20 security updates is an alert, fewer is a note.
- **`gather_context(info)`** — journal error count this boot and the
  `/var/run/reboot-required` flag (dropped by kernel/libc updates);
  context, never an alert.
- **`check_battery(info)`** — reads `energy_full` vs
  `energy_full_design` (or the `charge_*` pair, depending on driver)
  from `/sys/class/power_supply/BAT*`. Notes wear only below 80% of
  design capacity — a healthy battery stays silent.
- **`main()`** — the two-track send: no issues → a one-line
  `🩺✅ all-clear` with the notes inline (no model call needed). Issues →
  one model call turns raw findings into 2–3 terse sentences leading
  with what to do; if that API call fails, the RAW findings are sent
  instead — an alert must never be lost to an API failure (boot-time
  catch-up runs can beat Wi-Fi). The ⚠️/✅ icon is the at-a-glance signal.
- **`agentlib`** is imported from `~/agents/common/` via `sys.path` —
  local agents share one copy instead of vendoring.

- Tests run in CI on every push (`.github/workflows/tests.yml`).

## Ops (systemd, not GitHub Actions)

- Units: `~/.config/systemd/user/housekeeper.{service,timer}` — live
  copies; `systemd/` in this repo holds reference copies —
  06:00 IST, `Persistent=true` (missed runs fire on next boot/wake),
  `Restart=on-failure` every 2 min, max 5 tries per 30 min (network
  races at boot).
- Logs: `journalctl --user -u housekeeper.service -e`
- Run now: `systemctl --user start housekeeper.service`
- Secrets: `~/agents/housekeeper/.env` (chmod 600)
