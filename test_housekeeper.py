#!/usr/bin/env python3
"""Offline unit tests for housekeeper — no shelling out, no systemd.

Every check that shells out is driven through a stubbed `sh`; the battery
check reads a tmpdir fake sysfs. Covers: apt parsing and thresholds,
ignored-units filtering, vault drift messages, battery wear, reboot flag
absence handling.
"""

import tempfile
import unittest
from pathlib import Path

import housekeeper as hk


def stub_sh(mapping):
    """An sh() replacement answering by substring match on the command."""

    def fake(cmd):
        for needle, out in mapping.items():
            if needle in cmd:
                return out
        return ""

    return fake


class UpdatesTest(unittest.TestCase):

    def _run(self, listing):
        issues, info = [], []
        saved = hk.sh
        hk.sh = stub_sh({"apt list": listing})
        try:
            hk.check_updates(issues, info)
        finally:
            hk.sh = saved
        return issues, info

    def test_counts_and_notes(self):
        listing = "Listing...\npkg1/now-security 1.0 amd64\npkg2/stable 2.0 amd64"
        issues, info = self._run(listing)
        self.assertEqual(issues, [])
        self.assertIn("1 security updates pending", info)
        self.assertIn("2 apt packages upgradable total", info)

    def test_alert_threshold(self):
        listing = "Listing...\n" + "\n".join(
            f"pkg{i}/now-security 1.0" for i in range(25)
        )
        issues, _ = self._run(listing)
        self.assertTrue(any("SECURITY" in i for i in issues))


class FailedUnitsTest(unittest.TestCase):

    def test_ignored_units_filtered(self):
        issues = []
        saved = hk.sh
        hk.sh = stub_sh({
            "systemctl --failed": "casper-md5check.service loaded failed failed",
            "systemctl --user --failed": "myjob.service loaded failed failed",
        })
        try:
            hk.check_failed_units(issues)
        finally:
            hk.sh = saved
        self.assertEqual(len(issues), 1)
        self.assertIn("myjob.service", issues[0])
        self.assertNotIn("casper", issues[0])


class VaultTest(unittest.TestCase):

    def test_dirty_with_no_commits_reads_honestly(self):
        if not (hk.VAULT_DIR / ".git").exists():
            self.skipTest("no vault on this machine")
        issues, info = [], []
        saved = hk.sh
        hk.sh = stub_sh({"status --porcelain": " M note.md", "log -1": "",
                         "remote": ""})
        try:
            hk.check_vault(issues, info)
        finally:
            hk.sh = saved
        self.assertTrue(any("no commits yet" in i for i in info))
        self.assertNotIn("None", " ".join(issues + info))


class BatteryTest(unittest.TestCase):

    def _run(self, full, design, prefix="energy"):
        info = []
        with tempfile.TemporaryDirectory() as tmp:
            bat = Path(tmp) / "BAT0"
            bat.mkdir()
            (bat / f"{prefix}_full").write_text(str(full))
            (bat / f"{prefix}_full_design").write_text(str(design))
            hk.check_battery(info, base=Path(tmp))
        return info

    def test_worn_battery_noted(self):
        info = self._run(70_000_000, 100_000_000)
        self.assertTrue(any("70% of design" in i for i in info))

    def test_healthy_battery_stays_silent(self):
        self.assertEqual(self._run(92_000_000, 100_000_000), [])

    def test_charge_prefix_variant(self):
        info = self._run(3_000_000, 5_000_000, prefix="charge")
        self.assertTrue(any("60% of design" in i for i in info))




class MemoryLoadTest(unittest.TestCase):

    def _proc(self, tmp, avail_kb, total_kb=16000000, load="0.5"):
        meminfo = Path(tmp) / "meminfo"
        meminfo.write_text(
            f"MemTotal: {total_kb} kB\nMemAvailable: {avail_kb} kB\n"
            "SwapTotal: 2000000 kB\nSwapFree: 500000 kB\n")
        loadavg = Path(tmp) / "loadavg"
        loadavg.write_text(f"{load} 0.4 0.3 1/500 999\n")
        return str(meminfo), str(loadavg)

    def test_pressure_alerts_swap_noted(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            meminfo, loadavg = self._proc(tmp, avail_kb=800000)  # 5%
            issues, info = [], []
            saved = hk.sh
            hk.sh = lambda cmd: "chrome 4000000\nfirefox 2000000"
            try:
                hk.check_memory_load(issues, info, meminfo, loadavg)
            finally:
                hk.sh = saved
        self.assertTrue(any("memory pressure" in i for i in issues))
        self.assertTrue(any("swap 75% used" in i for i in info))

    def test_healthy_memory_quiet(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            meminfo, loadavg = self._proc(tmp, avail_kb=8000000)  # 50%
            issues, info = [], []
            hk.check_memory_load(issues, info, meminfo, loadavg)
        self.assertEqual(issues, [])


class TempsTest(unittest.TestCase):

    def _zone(self, tmp, milli):
        z = Path(tmp) / "thermal_zone0"
        z.mkdir()
        (z / "temp").write_text(str(milli))

    def test_hot_alerts_warm_notes_cool_silent(self):
        import tempfile
        for milli, in_issues, in_info in ((90000, True, False),
                                          (75000, False, True),
                                          (50000, False, False)):
            with tempfile.TemporaryDirectory() as tmp:
                self._zone(tmp, milli)
                issues, info = [], []
                hk.check_temps(issues, info, base=Path(tmp))
            self.assertEqual(bool(issues), in_issues, milli)
            self.assertEqual(bool(info), in_info, milli)


class KernelErrorsAndTimersTest(unittest.TestCase):

    def test_storage_errors_alert(self):
        saved = hk.sh
        hk.sh = lambda cmd: "3"
        try:
            issues = []
            hk.check_kernel_errors(issues)
        finally:
            hk.sh = saved
        self.assertTrue(any("storage error" in i for i in issues))

    def test_clean_kernel_log_silent(self):
        saved = hk.sh
        hk.sh = lambda cmd: "0"
        try:
            issues = []
            hk.check_kernel_errors(issues)
        finally:
            hk.sh = saved
        self.assertEqual(issues, [])

    def test_missing_timer_alerts(self):
        saved = hk.sh
        hk.sh = lambda cmd: "someother.timer   Mon ..."  # housekeeper absent
        try:
            issues = []
            hk.check_local_timers(issues)
        finally:
            hk.sh = saved
        self.assertEqual(len(issues), 1)
        self.assertIn("housekeeper.timer", issues[0])


class FleetWatchdogTest(unittest.TestCase):

    from datetime import date as _date
    MONDAY = _date(2026, 7, 6)   # yesterday = Sunday (weekday 6)
    SUNDAY = _date(2026, 7, 12)  # yesterday = Saturday (weekday 5) → papers due

    def _fleet(self, reply_by_repo, today):
        def fake_sh(cmd):
            for repo, reply in reply_by_repo.items():
                if repo in cmd:
                    return reply
            return "[]"
        saved = hk.sh
        hk.sh = fake_sh
        try:
            issues, info = [], []
            hk.check_fleet(issues, info, today=today)
            return issues, info
        finally:
            hk.sh = saved

    def test_all_ran_is_one_quiet_note(self):
        ok = '[{"event": "workflow_dispatch", "conclusion": "success"}]'
        issues, info = self._fleet(
            {r: ok for r, _, _ in hk.CLOUD_AGENTS}, today=self.MONDAY)
        self.assertEqual(issues, [])
        self.assertTrue(any("ran yesterday ✓" in i for i in info))

    def test_silent_agent_alerts(self):
        ok = '[{"event": "schedule", "conclusion": "success"}]'
        replies = {r: ok for r, _, _ in hk.CLOUD_AGENTS}
        replies["astroboy1183/mail-digest"] = "[]"
        issues, _ = self._fleet(replies, today=self.MONDAY)
        self.assertEqual(len(issues), 1)
        self.assertIn("mail DID NOT RUN", issues[0])

    def test_fired_but_failed_alerts(self):
        ok = '[{"event": "schedule", "conclusion": "success"}]'
        replies = {r: ok for r, _, _ in hk.CLOUD_AGENTS}
        replies["astroboy1183/tech-news"] = '[{"event": "schedule", "conclusion": "failure"}]'
        issues, _ = self._fleet(replies, today=self.MONDAY)
        self.assertIn("tech fired but never succeeded", issues[0])

    def test_weekly_checked_only_morning_after(self):
        ok = '[{"event": "schedule", "conclusion": "success"}]'
        replies = {r: ok for r, _, _ in hk.CLOUD_AGENTS}
        replies["astroboy1183/papers-digest"] = "[]"
        issues, _ = self._fleet(replies, today=self.MONDAY)   # papers not due
        self.assertEqual(issues, [])
        issues, _ = self._fleet(replies, today=self.SUNDAY)   # Sat was yesterday
        self.assertIn("papers DID NOT RUN", issues[0])

    def test_offline_gh_is_one_note_not_alarm(self):
        saved = hk.sh
        hk.sh = lambda cmd: ""
        try:
            issues, info = [], []
            hk.check_fleet(issues, info, today=self.MONDAY)
        finally:
            hk.sh = saved
        self.assertEqual(issues, [])
        self.assertTrue(any("gh unreachable" in i for i in info))


class AgentlibDriftTest(unittest.TestCase):

    def test_drift_alerts_sync_silent(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "common").mkdir()
            (base / "common" / "agentlib.py").write_text("REF")
            (base / "good").mkdir()
            (base / "good" / "agentlib.py").write_text("REF")
            (base / "bad").mkdir()
            (base / "bad" / "agentlib.py").write_text("DRIFTED")
            issues = []
            hk.check_agentlib_drift(issues, base=base)
        self.assertEqual(len(issues), 1)
        self.assertIn("bad", issues[0])
        self.assertNotIn("good", issues[0])


class CleanupTest(unittest.TestCase):

    def test_ledger_itemizes_only_big_things(self):
        def fake_sh(cmd):
            if cmd.startswith("du") and ".cache" in cmd:
                return f"{7 * 2**30} /home/x/.cache"     # 7G → itemized
            if cmd.startswith("du"):
                return f"{100 * 2**20} /home/x/Trash"    # 0.1G → quiet
            if "disk-usage" in cmd:
                return "Archived and active journals take up 3.5G in the file system."
            if "autoremove" in cmd:
                return "4"
            return ""
        saved = hk.sh
        hk.sh = fake_sh
        try:
            info = []
            hk.check_cleanup(info)
        finally:
            hk.sh = saved
        self.assertEqual(len(info), 1)
        line = info[0]
        self.assertIn("~/.cache 7.0G", line)
        self.assertIn("journald 3.5G", line)
        self.assertIn("4 packages autoremovable", line)
        self.assertNotIn("trash", line)


class TrendsTest(unittest.TestCase):

    def test_disk_growth_noted(self):
        history = {"2026-07-01": {"disk": 60}}
        issues, info = [], []
        hk.apply_trends(issues, info, history, 67, False, today="2026-07-11")
        self.assertTrue(any("grew 7%" in i for i in info))
        self.assertEqual(history["2026-07-11"], {"disk": 67})

    def test_fresh_reboot_flag_is_note_old_is_alert(self):
        history = {}
        issues, info = [], []
        hk.apply_trends(issues, info, history, 50, True, today="2026-07-11")
        self.assertTrue(any("reboot required" in i for i in info))
        self.assertEqual(issues, [])
        self.assertEqual(history["reboot_since"], "2026-07-11")

        history = {"reboot_since": "2026-07-01"}
        issues, info = [], []
        hk.apply_trends(issues, info, history, 50, True, today="2026-07-11")
        self.assertTrue(any("ignored for 10 days" in i for i in issues))

    def test_reboot_clears_when_flag_gone(self):
        history = {"reboot_since": "2026-07-01"}
        hk.apply_trends([], [], history, 50, False, today="2026-07-11")
        self.assertNotIn("reboot_since", history)


if __name__ == "__main__":
    unittest.main(verbosity=2)
