import json
import gzip
import tempfile
import unittest
from pathlib import Path

from shared_utils.nvd_feed_parse import iter_cve_dicts_from_nvd_root, iter_cve_rows_from_gzip


class TestNvdFeedParse(unittest.TestCase):
    def test_vulnerabilities_2_0(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-02T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Test desc"}],
                    }
                }
            ]
        }
        rows = list(iter_cve_dicts_from_nvd_root(data))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cve_id"], "CVE-2024-0001")
        self.assertEqual(rows[0]["description"], "Test desc")
        self.assertIn("2024-01-01", rows[0]["published"] or "")

    def test_legacy_cve_items(self) -> None:
        data = {
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": {"ID": "CVE-2020-99999"},
                        "publishedDate": "2020-06-01T00:00Z",
                        "lastModifiedDate": "2020-06-02T00:00Z",
                        "description": {
                            "description_data": [{"value": "Legacy"}],
                        },
                    }
                }
            ]
        }
        rows = list(iter_cve_dicts_from_nvd_root(data))
        self.assertEqual(rows[0]["cve_id"], "CVE-2020-99999")
        self.assertEqual(rows[0]["description"], "Legacy")

    def test_roundtrip_gzip(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2025-7777",
                        "published": "2025-01-01T00:00:00.000",
                        "lastModified": "2025-01-01T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Gz"}],
                    }
                }
            ]
        }
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "nvdcve-2.0-test.json.gz"
            with gzip.open(p, "wt", encoding="utf-8") as f:
                json.dump(data, f)
            rows = list(iter_cve_rows_from_gzip(p))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["cve_id"], "CVE-2025-7777")


if __name__ == "__main__":
    unittest.main()
