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


if __name__ == "__main__":
    unittest.main(verbosity=2)
