import tempfile
import unittest
from pathlib import Path

from shared_utils.cti_pipelines import run_asm_export, run_cve_nvd_update_export
from shared_utils.db_manager import CTIVault


class TestPipelines(unittest.TestCase):
    def test_run_cve_nvd_update_export(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            v = CTIVault(workspace_root=root)
            v.init_schema()
            run_cve_nvd_update_export(
                v,
                [{"cve_id": "CVE-2021-1", "description": "d"}],
                csv_path=root / "a.csv",
            )
            self.assertTrue((root / "a.csv").is_file())
            self.assertIn("CVE-2021-1", (root / "a.csv").read_text(encoding="utf-8"))

    def test_run_asm_export(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            v = CTIVault(workspace_root=root)
            v.init_schema()
            run_asm_export(
                v,
                assets=[
                    {
                        "asset_target": "e.com",
                        "port": 443,
                        "protocol": "tcp",
                    }
                ],
                csv_path=root / "asm.csv",
            )
            self.assertIn("e.com", (root / "asm.csv").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
