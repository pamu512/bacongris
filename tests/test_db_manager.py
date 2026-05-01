import os
import tempfile
import time
import unittest
from pathlib import Path

from shared_utils.db_manager import CTIVault, CURRENT_SCHEMA_VERSION


class TestCTIVault(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_init_and_cve_upsert_export(self) -> None:
        v = CTIVault(workspace_root=self.root)
        n = v.init_schema()
        self.assertEqual(n, CURRENT_SCHEMA_VERSION)
        v.upsert_cve_row(
            cve_id="CVE-2024-0001",
            description="test",
        )
        out = self.root / "out.csv"
        v.export_cve_csv(out)
        self.assertTrue(out.is_file())
        text = out.read_text(encoding="utf-8")
        self.assertIn("CVE-2024-0001", text)
        self.assertIn("description", text)

    def test_cve_first_seen_preserved(self) -> None:
        v = CTIVault(workspace_root=self.root)
        v.init_schema()
        v.upsert_cve_row(cve_id="CVE-2020-1", first_seen="2020-01-01T00:00:00Z", description="a")
        v.upsert_cve_row(cve_id="CVE-2020-1", description="b")
        c = v.connect()
        row = c.execute("SELECT first_seen, description FROM cve_data WHERE cve_id=?", ("CVE-2020-1",)).fetchone()
        assert row is not None
        self.assertEqual(str(row[0]), "2020-01-01T00:00:00Z")
        self.assertEqual(str(row[1]), "b")

    def test_ioc_on_conflict(self) -> None:
        v = CTIVault(workspace_root=self.root)
        v.init_schema()
        v.upsert_ioc_row(
            ioc_value="1.1.1.1",
            ioc_type="ipv4",
            first_seen="2021-01-01T00:00:00Z",
        )
        v.upsert_ioc_row(
            ioc_value="1.1.1.1",
            ioc_type="ipv4",
        )
        r = v.connect().execute(
            "SELECT first_seen FROM ioc_records WHERE ioc_value=? AND ioc_type=?",
            ("1.1.1.1", "ipv4"),
        ).fetchone()
        assert r is not None
        self.assertIn("2021", str(r[0]))

    def test_check_sync_csv_stale_after_db_newer(self) -> None:
        v = CTIVault(workspace_root=self.root)
        v.init_schema()
        csv_path = self.root / "export.csv"
        csv_path.write_text("old", encoding="utf-8")
        old = time.time() - 100.0
        os.utime(csv_path, (old, old))
        v.upsert_cve_row(cve_id="CVE-2025-1", description="n")
        r = v.check_sync(csv_path, domain="cve")
        self.assertTrue(r.csv_is_stale)
        self.assertTrue(r.csv_exists)
        v.export_cve_csv(csv_path)
        r2 = v.check_sync(csv_path, domain="cve")
        self.assertFalse(r2.csv_is_stale)

    def test_check_sync_missing_csv_with_data(self) -> None:
        v = CTIVault(workspace_root=self.root)
        v.init_schema()
        v.upsert_cve_row(cve_id="CVE-2025-2", description="x")
        r = v.check_sync(self.root / "missing.csv", domain="cve")
        self.assertTrue(r.csv_is_stale)
        self.assertFalse(r.csv_exists)

    def test_wal_checkpoint_runs(self) -> None:
        v = CTIVault(workspace_root=self.root)
        v.init_schema()
        v.upsert_cve_batch(
            [{"cve_id": "CVE-2025-3", "description": "a"}],
            wal_checkpoint_after=True,
        )
        out = v.wal_checkpoint("PASSIVE")
        if out is not None:
            self.assertEqual(len(out), 3)


if __name__ == "__main__":
    unittest.main()
