import tempfile
import unittest
from pathlib import Path

from shared_utils.db_manager import open_cti_vault


class TestOpenCtiVault(unittest.TestCase):
    def test_closes_after_context(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with open_cti_vault(workspace_root=root) as v:
                v.upsert_ioc_row(ioc_value="1.1.1.1", ioc_type="ipv4")
            with open_cti_vault(workspace_root=root) as v2:
                c = v2.connect().execute(
                    "SELECT COUNT(*) FROM ioc_records WHERE ioc_value=?",
                    ("1.1.1.1",),
                ).fetchone()
                self.assertEqual(int(c[0] if c else 0), 1)


if __name__ == "__main__":
    unittest.main()
